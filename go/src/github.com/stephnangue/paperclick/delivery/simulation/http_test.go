package simulation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	generator "github.com/stephnangue/paperclick/delivery/certification"
	"github.com/stephnangue/paperclick/models"
	"github.com/stephnangue/paperclick/testdata"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type mockDatastore struct{}

func (m mockDatastore) GetExamSimulations(examId string) ([]models.Simulation, error) {
	var sims []models.Simulation
	if examId == "157966878099ee0b8deafda4" {
		for i := 0; i < 1; i++ {
			idObject, err1 := primitive.ObjectIDFromHex("654c175f0d7057e5c5b6adf9")
			if err1 != nil {
				panic(err1)
			}
			sims = append(sims, models.Simulation{ID: idObject})
		}
		return sims, nil
	}
	return sims, nil
}

func (m mockDatastore) Get(simulationId string) ([]models.Simulation, error) {
	if simulationId == "d274592346a8d9977d041a70" {
		idObject, err1 := primitive.ObjectIDFromHex(simulationId)
		if err1 != nil {
			panic(err1)
		}
		sim := models.Simulation{}
		sim.ID = idObject
		return []models.Simulation{sim}, nil
	}
	return []models.Simulation{}, nil
}

func (m mockDatastore) Create(examId string, simulation models.Simulation) (string, error) {
	return "successful", nil
}

func (m mockDatastore) Update(simulationId string, simulation models.Simulation) (string, error) {
	return "successful", nil
}

type certMockDatastore struct{}

func (m certMockDatastore) Get(code string) ([]models.Certification, error) {
	return nil, nil
}

func (m certMockDatastore) Create(certi models.Certification) (string, error) {
	return "", nil
}

func (m certMockDatastore) CreateExams(code string, exams []models.Exam) (string, error) {
	return "", nil
}

func (m certMockDatastore) GetExams(certificationCode string) ([]models.Exam, error) {
	return nil, nil
}

func (m certMockDatastore) GetExam(examId string) ([]models.Exam, error) {
	q1 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 20},
		QuestionQuantity: 50,
	}
	q2 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 17},
		QuestionQuantity: 50,
	}

	certi := testdata.GenerateCertification("CERT", 1, 37, []testdata.QuestionsPerDomain{q1, q2})
	exams, err := generator.GenerateExams(1, certi)
	if err != nil {
		panic(err)
	}
	if examId == "ec118508ffd1daf97adfa538" {
		idObject, err1 := primitive.ObjectIDFromHex(examId)
		if err1 != nil {
			panic(err1)
		}
		exams[len(exams)-1].ID = idObject
		return exams, nil
	}
	return []models.Exam{}, nil
}

var router *gin.Engine
var simDatastore mockDatastore
var certDatastore certMockDatastore
var handler SimulationHandler

func init() {
	router = gin.Default()
	simDatastore = mockDatastore{}
	certDatastore = certMockDatastore{}
	handler = NewSimulationHandler(simDatastore, certDatastore)

	router.GET("/v1/simulations/:simulationId", handler.Get)
	router.GET("/v1/simulations", handler.GetExamSimulations)
	router.POST("/v1/simulation", handler.Create)
	router.PUT("/v1/simulations/:simulationId", handler.Update)
}

func TestGet(t *testing.T) {
	testcases := []struct {
		simulationId string
		returnCode   int
		respBody     []byte
	}{
		{"d274592346a8d9977d041a70", 200, []byte(`{"result":[{"id":"d274592346a8d9977d041a70","examId":null,"startedAt":"0001-01-01T00:00:00Z","endedAt":"0001-01-01T00:00:00Z","questions":null}]}`)},
		{"FAKE", 404, []byte("there is no simulation with that ID")},
	}

	for _, v := range testcases {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v1/simulations/"+v.simulationId, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, v.returnCode, w.Code)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}

func TestGetExamSimulations(t *testing.T) {
	testcases := []struct {
		examId     string
		returnCode int
		respBody   []byte
	}{
		{"157966878099ee0b8deafda4", 200, []byte(`{"result":[{"id":"654c175f0d7057e5c5b6adf9","examId":null,"startedAt":"0001-01-01T00:00:00Z","endedAt":"0001-01-01T00:00:00Z","questions":null}]}`)},
		{"157966878099ef0b8deafda4", 200, []byte(`{"result":null}`)},
		{"", 400, []byte("you should provide the exam ID")},
	}
	for _, v := range testcases {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v1/simulations?examId="+v.examId, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, v.returnCode, w.Code)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}

func TestCreate(t *testing.T) {
	q1 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 20},
		QuestionQuantity: 50,
	}
	q2 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 17},
		QuestionQuantity: 50,
	}

	certi := testdata.GenerateCertification("CERT", 1, 37, []testdata.QuestionsPerDomain{q1, q2})
	exams, _ := generator.GenerateExams(1, certi)
	sim, _ := GenerateSimulation(exams[0])
	simByte, _ := json.Marshal(sim)

	testcases := []struct {
		requestBody []byte
		examId      string
		returnCode  int
		respBody    []byte
	}{
		{simByte, "ec118508ffd1daf97adfa538", 200, []byte(`{"result":"successful"}`)},
		{simByte, "ec118508ffd1daf97adfa539", 400, []byte(`there are no exam with that id`)},
	}

	for _, v := range testcases {
		reader := bytes.NewReader(v.requestBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/simulation?examId="+v.examId, reader)
		router.ServeHTTP(w, req)
		assert.Equal(t, v.returnCode, w.Code)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}

func TestUpdate(t *testing.T) {
	q1 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 20},
		QuestionQuantity: 50,
	}
	q2 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 17},
		QuestionQuantity: 50,
	}

	certi := testdata.GenerateCertification("CERT", 1, 37, []testdata.QuestionsPerDomain{q1, q2})
	exams, _ := generator.GenerateExams(1, certi)
	sim, _ := GenerateSimulation(exams[0])
	simByte, _ := json.Marshal(sim)

	testcases := []struct {
		requestBody []byte
		examId      string
		returnCode  int
		respBody    []byte
	}{
		{simByte, "ec118508ffd1daf97adfa538", 200, []byte(`{"result":"successful"}`)},
		{simByte, "ec118508ffd1daf97adfa539", 200, []byte(`{"result":"successful"}`)},
	}
	for _, v := range testcases {
		reader := bytes.NewReader(v.requestBody)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/v1/simulations/:simulationId?examId="+v.examId, reader)
		router.ServeHTTP(w, req)
		assert.Equal(t, v.returnCode, w.Code)
		assert.Equal(t, string(v.respBody), w.Body.String())
	}
}
