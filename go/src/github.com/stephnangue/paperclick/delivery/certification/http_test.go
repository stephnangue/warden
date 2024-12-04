package certification

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stephnangue/paperclick/models"
	"github.com/stephnangue/paperclick/testdata"
	"github.com/stretchr/testify/assert"
)

type mockDatastore struct{}

func (m mockDatastore) Get(code string) ([]models.Certification, error) {
	switch code {
	case "FAKE":
		return nil, errors.New("db error")
	case "AWS-SSA-01":
		q1 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 20},
			QuestionQuantity: 50,
		}
		q2 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 17},
			QuestionQuantity: 50,
		}
		certi := testdata.GenerateCertification("AWS-SSA-01", 2, 37, []testdata.QuestionsPerDomain{q1, q2})

		return []models.Certification{certi}, nil
	case "CERT-WITH-EXAMS":
		q1 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 20},
			QuestionQuantity: 50,
		}
		q2 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 17},
			QuestionQuantity: 50,
		}
		certi := testdata.GenerateCertification("CERT", 1, 37, []testdata.QuestionsPerDomain{q1, q2})

		exams, err := GenerateExams(certi.ExamQuantity, certi)
		if err != nil {
			log.Print(err)
		}
		certi.Exams = exams
		return []models.Certification{certi}, nil
	case "CERT-WITH-BAD-QUESTION-QTY":
		q1 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 100},
			QuestionQuantity: 50,
		}
		q2 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 67},
			QuestionQuantity: 50,
		}

		certi := testdata.GenerateCertification("CERT", 2, 167, []testdata.QuestionsPerDomain{q1, q2})
		return []models.Certification{certi}, nil
	case "CERT-WITH-DOMAIN-WITH-NO-QUESTIONS":
		q1 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 10},
			QuestionQuantity: 50,
		}
		q2 := testdata.QuestionsPerDomain{
			Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 7},
			QuestionQuantity: 0,
		}

		certi := testdata.GenerateCertification("CERT", 2, 167, []testdata.QuestionsPerDomain{q1, q2})
		return []models.Certification{certi}, nil
	default:
		return []models.Certification{{
			Code:             "GOOD-CERT",
			Name:             "AWS SAA",
			Description:      "AWS SAA Description",
			QuestionQuantity: 65,
			Duration:         230,
			PassingScore:     720,
			ExamQuantity:     4,
			Domains:          []models.Domain{},
			Exams:            []models.Exam{},
		}}, nil
	}
}

func (m mockDatastore) Create(certi models.Certification) (string, error) {
	if certi.Code == "FAKE" {
		return "", errors.New("Could not create certification")
	}
	return certi.Code, nil
}

func (m mockDatastore) CreateExams(code string, exams []models.Exam) (string, error) {
	if code == "AWS-SSA-01" {
		return "\"MatchedCount\":1,\"ModifiedCount\":1", nil
	} else {
		return "", errors.New("Could not create exams")
	}

}

func (m mockDatastore) GetExams(certificationCode string) ([]models.Exam, error) {
	if certificationCode == "AWS-SSA-01" {
		return []models.Exam{}, nil
	}
	return []models.Exam{}, nil
}

func (m mockDatastore) GetExam(examId string) ([]models.Exam, error) {
	if examId == "ATEST" {
		return []models.Exam{}, nil
	}
	return []models.Exam{}, nil
}

var router *gin.Engine
var datastore mockDatastore
var handler CertificationHandler

func init() {
	router = gin.Default()
	datastore = mockDatastore{}
	handler = NewCertificationHandler(datastore)

	router.GET("/v1/certifications/:code", handler.Get)
	router.GET("/v1/certifications/:code/exams", handler.GetExams)
	router.POST("/v1/certification", handler.Create)
	router.PATCH("/v1/certifications/:code/exams", handler.CreateExams)
}

func TestGet(t *testing.T) {
	testcases := []struct {
		certCode   string
		returnCode int
		respBody   []byte
	}{
		{"GOOD-CERT", 200, []byte(`{"result":[{"id":null,"code":"GOOD-CERT","name":"AWS SAA","description":"AWS SAA Description","questionQuantity":65,"duration":230,"passingScore":720,"examQuantity":4,"domains":[],"exams":[]}]}`)},
		{"FAKE", 500, []byte("db error")},
		{"", 404, []byte("404 page not found")},
	}

	for _, v := range testcases {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v1/certifications/"+v.certCode, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, v.returnCode, w.Code)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}

func TestGetExams(t *testing.T) {
	testcases := []struct {
		certCode   string
		returnCode int
		respBody   []byte
	}{
		{"AWS-SSA-01", 200, []byte(`{"result":[]}`)},
		{"FAKE", 200, []byte(`{"result":[]}`)},
		{"", 200, []byte(`{"result":[]}`)},
	}

	for _, v := range testcases {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v1/certifications/"+v.certCode+"/exams", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, v.returnCode, w.Code)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}

func TestCreate(t *testing.T) {
	testcases := []struct {
		reqBody  []byte
		respBody []byte
	}{
		{[]byte(`{"code":"AWS-SSA-01","name":"AWS SAA","description":"AWS SAA Description","questionQuantity":65,"duration":230,"passingScore":720}`), []byte(`{"result":"AWS-SSA-01"}`)},
		{[]byte(`{"code":"FAKE","name":"AWS SAA","description":"AWS SAA Description","questionQuantity":65,"duration":230,"passingScore":720}`), []byte(`Could not create certification`)},
	}

	for _, v := range testcases {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/certification", bytes.NewReader(v.reqBody))
		router.ServeHTTP(w, req)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}

func TestCreateExams(t *testing.T) {
	testcases := []struct {
		certCode   string
		returnCode int
		respBody   []byte
	}{
		{"AWS-SSA-01", 200, []byte(`{"result":"\"MatchedCount\":1,\"ModifiedCount\":1"}`)},
		{"FAKE", 500, []byte(`db error`)},
		{"CERT-WITH-EXAMS", 400, []byte(`the certification with code CERT-WITH-EXAMS already contains 1 exam(s)`)},
		{"CERT-WITH-BAD-QUESTION-QTY", 500, []byte(`the number of questions (100) should not be greater than number of questions available (50) for the domain "Domain1"`)},
		{"CERT-WITH-DOMAIN-WITH-NO-QUESTIONS", 500, []byte(`the domain "Domain2" has no questions`)},
	}

	for _, v := range testcases {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PATCH", "/v1/certifications/"+v.certCode+"/exams", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, v.returnCode, w.Code)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}
