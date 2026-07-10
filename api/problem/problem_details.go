package problem

import "net/http"

const (
	InternalError   = "Internal Error"
	BadRequest      = "Bad Request"
	Unauthorized    = "Unauthorized"
	Forbidden       = "Forbidden"
	NotFound        = "Not Found"
	Conflict        = "Conflict"
	TooManyRequests = "Too Many Requests"
)

const errorType = "https://latebit.io/an/errors/"

// Details RFC 7807: Problem Details
type Details struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// NewServerError deliberately omits the underlying error text — internal
// errors (SQL, driver state) must not leak to API clients.
func NewServerError(err error) Details {
	return Details{
		Type:   errorType,
		Title:  InternalError,
		Status: http.StatusInternalServerError,
		Detail: "an unexpected error occurred",
	}
}

func NewBadRequest(err error) Details {
	return Details{
		Type:   errorType,
		Title:  BadRequest,
		Status: http.StatusBadRequest,
		Detail: err.Error(),
	}
}

func NewUnauthorized(detail string) Details {
	return Details{
		Type:   errorType,
		Title:  Unauthorized,
		Status: http.StatusUnauthorized,
		Detail: detail,
	}
}

func NewProblem(title string, status int, err error) Details {
	return Details{
		Type:   errorType,
		Status: status,
		Title:  title,
		Detail: err.Error(),
	}
}
