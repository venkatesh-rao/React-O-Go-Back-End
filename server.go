package main

import (
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type (
	// Book represent the struct to a book
	Book struct {
		Isbn   string `json: "isbn"`
		Title  string `json: "title"`
		Author string `json: "author"`
		Price  string `json: "price"`
	}

	// User represent the struct of a user
	User struct {
		Username string `json: "username"`
		Password string `json: "password"`
	}
)

type users = map[string]string

// HashPassword hashes the user given password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordWithHash checks the user given password with the existing hashpassword in the db
func CheckPasswordWithHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Welcome Home!")
}

func signIn(s *mgo.Session) echo.HandlerFunc {
	return func(c echo.Context) error {
		session := s.Copy()
		defer session.Close()

		user := new(User)

		if err := c.Bind(&user); err != nil {
			return err
		}

		username := user.Username
		password := user.Password

		check := new(User)

		if err := session.DB("store").C("users").Find(bson.M{"username": username}).One(&check); err != nil {
			return echo.ErrUnauthorized
		}

		if username == check.Username && CheckPasswordWithHash(password, check.Password) {

			// Create token
			token := jwt.New(jwt.SigningMethodHS256)

			// // Set claims
			claims := token.Claims.(jwt.MapClaims)
			claims["name"] = "jon snow"
			claims["admin"] = true
			claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

			// Generate encoded token and send it as response
			t, err := token.SignedString([]byte("secret"))
			if err != nil {
				return err
			}
			return c.JSON(http.StatusOK, map[string]string{
				"token": t,
			})

		}

		return echo.ErrUnauthorized
	}
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

		if err := session.DB("store").C("books").Find(bson.M{"isbn": isbn}).All(&book); err != nil {
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

		if err := session.DB("store").C("books").Remove(bson.M{"isbn": isbn}); err != nil {
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

		if err := session.DB("store").C("books").Insert(book); err != nil {
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

		if err := session.DB("store").C("books").Update(bson.M{"isbn": isbn}, &book); err != nil {
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
	e.POST("/login", signIn(session))

	r := e.Group("/books")
	r.Use(middleware.JWT([]byte("secret")))

	r.GET("", allBooks(session))
	r.GET("/:isbn", findBookByNumber(session))
	r.POST("", addBook(session))
	r.PUT("/:isbn", updateBook(session))
	r.DELETE("/:isbn", deleteBookByNumber(session))

	e.Logger.Fatal(e.Start(":1234"))
}
