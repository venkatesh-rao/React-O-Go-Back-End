package main

import (
	"net/http"
	"time"
	
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Book struct {
	Isbn   string `json: "isbn"`
	Title  string `json: "title"`
	Author string `json: "author"`
	Price  string `json: "price"`
}


func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Welcome to the Store!")
}

func signIn(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	if username == "jon" && password == "hello" {
		// Create token
		token := jwt.New(jwt.SigningMethodHS256)

		// Set claims
		claims := token.Claims.(jwt.MapClaims)
		claims["name"] = "jon snow"
		claims["admin"] = true
		claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

		// Generate encoded token and send it as response
		t, err := token.SignedString([]byte("secret"))
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]string {
			"token": t,
		})
	}

	return echo.ErrUnauthorized
}

func allBooks(s *mgo.Session) echo.HandlerFunc {
    return func(c echo.Context) (err error) {
		session := s.Copy()
		defer session.Close()

		var books []Book
		if err := session.DB("store").C("books").Find(bson.M{}).All(&books); err != nil {
			return err
		}

		return c.JSONPretty(http.StatusOK, books, "  ")
	}
}

func findBookByNumber(s *mgo.Session) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		session := s.Copy()
		defer session.Close()

		isbn := c.Param("isbn")
		var book []Book
		
		if err := session.DB("store").C("books").Find(bson.M{"isbn": isbn}).All(&book); err !=nil {
			return err
		}

		return c.JSONPretty(http.StatusOK, book, "  ")
	}
}

func deleteBookByNumber(s *mgo.Session) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		session := s.Copy()
		defer session.Close()

		isbn := c.Param("isbn")

		if err := session.DB("store").C("books").Remove(bson.M{"isbn": isbn}); err !=nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)

	}
}

func addBook(s *mgo.Session) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		session := s.Copy()
		defer session.Close()

		book := new(Book)
		
		if err := c.Bind(&book); err != nil {
			return err
		}

		if err := session.DB("store").C("books").Insert(book); err !=nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)

	}
}

func updateBook(s *mgo.Session) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		session := s.Copy()
		defer session.Close()

		book := new(Book)
		isbn := c.Param("isbn")
		
		if err := c.Bind(&book); err != nil {
			return err
		}

		if err := session.DB("store").C("books").Update(bson.M{"isbn": isbn}, &book); err !=nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)

	}
}

func main() {
	e := echo.New()

	// CORS default
	// Allows requests from any origin wth GET, HEAD, PUT, POST or DELETE method.
	e.Use(middleware.CORS())

	// CORS restricted
	// Allows requests from any `https://123.com` or `https://123.net` origin
	// wth GET, PUT, POST or DELETE method.

	// e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
	// 	AllowOrigins: []string{"https://123.com", "https://123.net"},
	// 	AllowMethods: []string{echo.GET, echo.PUT, echo.POST, echo.DELETE},
	// }))

	session, err := mgo.Dial("mongodb://gobooks:gobooks@ds261429.mlab.com:61429/store")
	if err != nil {
	}

	defer session.Close()

	e.GET("/", hello)
	e.POST("/login", signIn)

	r := e.Group("/books")
	r.Use(middleware.JWT([]byte("secret")))
	
	r.GET("", allBooks(session))
	r.GET("/:isbn", findBookByNumber(session))
	r.POST("", addBook(session))
	r.PUT("/:isbn", updateBook(session))
	r.DELETE("/:isbn", deleteBookByNumber(session))
	
	e.Logger.Fatal(e.Start(":1234"))
}
