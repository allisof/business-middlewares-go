package auth

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	_ "github.com/lib/pq"
)

var (
	db   *sql.DB
	once sync.Once
)

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r responseBodyWriter) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func readBody(reader io.Reader) string {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(reader)
	if err != nil {
		log.Println(err)
	}

	s := buf.String()
	return s
}

// PostgresConnect Connect to the database
func postgresConnect(pgUri string) {
	once.Do(func() {
		var err error

		db, err = sql.Open("postgres", pgUri)
		if err != nil {
			log.Fatalf("Can't open db: %v\n", err)
		}

		if err = db.Ping(); err != nil {
			log.Fatalf("Can't do ping: %v\n", err)
		}
	})
}

// PostgresPool Returns a database connection
func postgresPool() *sql.DB {
	return db
}

func isValidAction(userId string, endpoint string, method string) (bool, error) {
	postgresConnect(os.Getenv("BUSINESS_IAM_SQL_DB"))
	db := postgresPool()

	const sqlQuery = `
		SELECT
			A.endpoint,
			A.method
		FROM users AS U
			JOIN user_groups AS UG ON UG.user_id = U.id
			JOIN groups AS G ON UG.group_id = G.id
			JOIN action_groups AS AG ON AG.group_id = G.id
			JOIN actions AS A ON AG.action_id = A.id
			JOIN options AS O ON A.option_id = O.id
			JOIN services AS S ON O.service_id = S.id
		WHERE
			S.status = $1
			AND O.status = $1
			AND A.status = $1
		  	AND U.status = $1
			AND A.endpoint = $2
			AND A.method = $3
			AND U.id = $4
	`
	stmt, err := db.Prepare(sqlQuery)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Println(err)
		}
	}()

	var endpointResult string
	var methodResult string

	err = stmt.QueryRow(
		"AVAILABLE",
		endpoint,
		method,
		userId,
	).Scan(
		&endpointResult,
		&methodResult,
	)
	if err != nil {
		return false, err
	}

	if endpointResult == endpoint && methodResult == method {
		return true, nil
	}

	return false, errors.New("error: unauthorized user")
}

func Check() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenBearer := c.Request.Header.Get("Authorization")
		method := c.Request.Method

		if c.FullPath() != "/api/iam/auth" {
			authUnauthorizedError := errors.New("error: unauthorized user")
			authForbiddenError := errors.New("error: user not authorized for this operation")

			if tokenBearer == "" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"code":    "UNAUTHORIZED_ERROR",
					"message": authUnauthorizedError.Error(),
				})
				c.Abort()
				return
			}

			jwtToken := strings.TrimPrefix(tokenBearer, "Bearer ")

			var jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
			token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("error: unauthorized user")
				}

				return jwtSecretKey, nil
			})

			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"code":    "UNAUTHORIZED_ERROR",
					"message": authUnauthorizedError.Error(),
				})
				c.Abort()
				return
			}

			var userId string
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				c.Set("agencyId", claims["agencyId"])
				c.Set("companyId", claims["companyId"])
				c.Set("userId", claims["userId"])
				c.Set("email", claims["email"])

				userId = fmt.Sprint(claims["userId"])
			}

			if ok, err := isValidAction(userId, c.FullPath(), method); !ok && err != nil {
				c.JSON(http.StatusForbidden, gin.H{
					"code":    "FORBIDDEN_ERROR",
					"message": authForbiddenError.Error(),
				})
				c.Abort()
				return
			}
		}

		var requestBody string

		if os.Getenv("MODE") == "DEBUGGER" {
			// Get request body
			buf, _ := io.ReadAll(c.Request.Body)
			rdr1 := io.NopCloser(bytes.NewBuffer(buf))
			rdr2 := io.NopCloser(bytes.NewBuffer(buf))

			requestBody = readBody(rdr1)
			c.Request.Body = rdr2
		}

		c.Next()

		if os.Getenv("MODE") == "DEBUGGER" {
			if requestBody != "" {
				fmt.Printf("Request Body: %v\n", requestBody)
			}

			// Get response body
			w := &responseBodyWriter{body: &bytes.Buffer{}, ResponseWriter: c.Writer}
			c.Writer = w

			fmt.Printf("Response body: %v\n", w.body.String())
		}
	}
}
