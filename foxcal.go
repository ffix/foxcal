package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	ical "github.com/arran4/golang-ical"
	loggerMiddleware "github.com/chi-middleware/logrus-logger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jinzhu/now"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

var log = logrus.New()
var baseDomain string
var rememberUserToken string
var refreshInterval = time.Duration(12) * time.Hour
var userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0"

func init() {
	//init logger
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	log.SetLevel(logrus.InfoLevel)

	// week starts from Monday
	now.WeekStartDay = time.Monday

	// set base domain
	baseDomain = os.Getenv("BASE_DOMAIN")
	if baseDomain == "" {
		log.Fatal("BASE_DOMAIN env variable is not set")
	}
	if _, err := url.ParseRequestURI(baseDomain); err != nil {
		log.Fatal("BASE_DOMAIN env variable is not a valid URL")
	}

	//set refresh interval
	refreshIntervalEnv := os.Getenv("REFRESH_INTERVAL_MINS")
	if refreshIntervalEnv == "" {
		log.Fatal("REFRESH_INTERVAL_MINS env variable is not set")
	}

	//parse refreshIntervalEnv to int
	refreshIntervalInt, err := strconv.Atoi(refreshIntervalEnv)
	if err != nil {
		log.Fatal("REFRESH_INTERVAL_MINS env variable is not a valid integer")
	}

	refreshInterval = time.Duration(refreshIntervalInt) * time.Minute

	//set user agent
	userAgentEnv := os.Getenv("USER_AGENT")
	if userAgentEnv != "" {
		userAgent = userAgentEnv
		log.Debugf("User agent is set to %s", userAgent)
	}

	rememberUserToken = os.Getenv("REMEMBER_USER_TOKEN")
	if rememberUserToken == "" {
		log.Fatal("REMEMBER_USER_TOKEN not found in environment variable")
	}

}

const (
	baseURL    = "%s/api/calendar?date_from=%s&date_to=%s"
	refererURL = "%s/elementary/dashboard/calendar"
)

type Event struct {
	StartsAt          time.Time `json:"starts_at"`
	Duration          int       `json:"duration"`
	URL               string    `json:"url"`
	Title             string    `json:"title"`
	Discipline        string    `json:"discipline_name"`
	Teacher           string    `json:"teacher_name"`
	Agent             string    `json:"agent_name"`
	IsOnlineAvailable bool      `json:"is_online_available"`
	IsVideoAvailable  bool      `json:"is_video_available"`
	IsAsync           bool      `json:"is_async"`
}

type EventsStorage struct {
	Lessons []Event `json:"course_lessons"`
}

type IcsStorage struct {
	calendar *string
	mu       sync.RWMutex
}

func (i *IcsStorage) Get() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return *i.calendar
}

func (i *IcsStorage) Set(calendar string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calendar = &calendar
}

type Calendar struct {
	ics        IcsStorage
	httpClient *http.Client
}

func NewCalendar() (*Calendar, error) {
	calendar := Calendar{}
	err := calendar.initHttpClient()
	if err != nil {
		return nil, err
	}
	err = calendar.updateCalendar()
	return &calendar, err
}

func (c *Calendar) updateCalendar() error {
	events, err := c.getCalendarFromASite()
	if err != nil {
		return fmt.Errorf("error reading JSON file: %w", err)
	}
	if calendar, err := GenerateICSFile(events); err == nil {
		c.ics.Set(calendar)
		log.Info("Calendar updated")
		return nil
	}
	return fmt.Errorf("error generating calendar: %w", err)
}

func (c *Calendar) CalendarUpdateLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			log.Info("Calendar update loop stopped")
			return
		case <-time.After(refreshInterval):
			err := c.updateCalendar()
			if err != nil {
				log.WithError(err).Warning("Error updating calendar")
			}
		}
	}
}

func (c *Calendar) GetCalendarHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/calendar")
	if _, err := w.Write([]byte(c.ics.Get())); err != nil {
		log.WithError(err).Warning("Error on handling calendar request")
	}
}

func (c *Calendar) initHttpClient() error {
	// Create a new cookie jar
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return fmt.Errorf("error creating cookie jar: %w", err)
	}

	// Create a new cookie with the remember_user_token value
	cookie := &http.Cookie{
		Name:  "remember_user_token",
		Value: rememberUserToken,
		Path:  "/",
		// Set the HttpOnly flag to true
		HttpOnly: true,
	}

	// Add the cookie to the cookie jar
	url, err := url.Parse(baseDomain)
	if err != nil {
		return fmt.Errorf("error parsing base domain: %w", err)
	}
	jar.SetCookies(url, []*http.Cookie{cookie})

	// Create a new client with the cookie jar
	client := &http.Client{
		Jar: jar,
	}

	c.httpClient = client
	return nil
}

func (c *Calendar) getCalendarFromASite() ([]Event, error) {
	left, right := getTimeRange()
	requestURL := fmt.Sprintf(baseURL, baseDomain, left.Format("2006-01-02"), right.Format("2006-01-02"))
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Referer", fmt.Sprintf(refererURL, baseDomain))

	log.Info("Requesting calendar from ", requestURL)
	resp, err := c.httpClient.Do(req)

	if err != nil {
		return nil, fmt.Errorf("error getting calendar from a site: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var foxcal EventsStorage
	err = json.Unmarshal(body, &foxcal)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %w", err)
	}
	log.Info(fmt.Sprintf("Got %d events", len(foxcal.Lessons)))
	return foxcal.Lessons, nil
}

func GenerateICSFile(events []Event) (string, error) {
	uniqueUUIDStorage := make(map[string]bool)
	hash := sha256.New()
	// Create a new ICS calendar
	cal := ical.NewCalendar()
	cal.Events()
	// Add events to the calendar
	for _, event := range events {
		hash.Write([]byte(event.URL))
		urlHash := hex.EncodeToString(hash.Sum(nil))
		if _, ok := uniqueUUIDStorage[urlHash]; ok {
			return "", fmt.Errorf("duplicate event URL: %s", event.URL)
		}
		uniqueUUIDStorage[urlHash] = true
		e := cal.AddEvent(urlHash)

		//e.SetDtStampTime(event.StartsAt)
		e.SetStartAt(event.StartsAt)
		err := e.SetDuration(time.Duration(event.Duration) * time.Minute)
		if err != nil {
			return "", fmt.Errorf("error setting duration: %w", err)
		}
		e.SetLocation(fmt.Sprintf("%s%s", baseDomain, event.URL))
		offlineSuffix := ""
		if !event.IsOnlineAvailable {
			offlineSuffix = " (offline)"
		}
		e.SetSummary(fmt.Sprintf("%s: %s%s", event.Discipline, event.Title, offlineSuffix))
		teacher := event.Agent
		if event.Agent == "" {
			teacher = event.Teacher
		}
		e.SetDescription(teacher)
	}

	// Generate the ICS data
	return cal.Serialize(), nil
}

func main() {
	calendar, err := NewCalendar()
	if err != nil {
		log.WithError(err).Fatal("Error creating calendar")
		os.Exit(1)
	}

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg.Add(1)
	go calendar.CalendarUpdateLoop(ctx, wg)

	r := chi.NewRouter()
	//r.Use(middleware.Logger)
	r.Use(loggerMiddleware.Logger("router", log))
	r.Use(middleware.Recoverer)
	r.Get("/calendar.ics", calendar.GetCalendarHandler)
	srv := &http.Server{Addr: ":3000", Handler: r}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.ListenAndServe()
		if err != nil {
			fmt.Println(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-sig
		cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.WithError(err).Error("error shutting down server")
		}
	}()

	wg.Wait()
	log.Info("Exiting application...")
}

func getTimeRange() (time.Time, time.Time) {
	prevMonday := now.BeginningOfWeek().AddDate(0, 0, -7)
	nextSunday := now.EndOfWeek().AddDate(0, 0, 7)
	return prevMonday, nextSunday
}
