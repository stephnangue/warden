package simulation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stephnangue/paperclick/driver"
	"github.com/stephnangue/paperclick/models"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const simulation_test = `
{
    "startedAt": "2023-01-02T2:04:05Z",
    "endedAt": "2023-01-02T4:04:05Z",
    "questions": [
        {
            "domain": "Design Secure Architectures",
            "stem": "A company runs a public-facing three-tier web application in a VPC across multiple Availability Zones.",
            "explanation": "A NAT gateway forwards traffic from the EC2 instances in the private subnet to the internet",
            "partialAnswerAllowed": false,
            "displayed": true,
            "answers": [
                {
                    "statement": "Configure a NAT gateway in a public subnet.",
                    "isCorrect": true,
                    "score": 10,
                    "selected": true
                },
                {
                    "statement": "Define a custom route table with a route to the NAT gateway for internet traffic and associate it with the private subnets for the application tier.",
                    "isCorrect": true,
                    "score": 10,
                    "selected": false
                },
                {
                    "statement": "Assign Elastic IP addresses to the EC2 instances.",
                    "isCorrect": false,
                    "score": 0,
                    "selected": true
                },
                {
                    "statement": "Define a custom route table with a route to the internet gateway for internet traffic and associate it with the private subnets for the application tier.",
                    "isCorrect": false,
                    "score": 0,
                    "selected": false
                },
                {
                    "statement": "Configure a NAT instance in a private subnet.",
                    "isCorrect": false,
                    "score": 0,
                    "selected": false
                }
            ]
        }
    ]
}
`

type result struct {
	InsertedId string `json:"InsertedID"`
}

func TestDatastore(t *testing.T) {
	collection, err := driver.GetCollection("paper", "simulations")
	if err != nil {
		t.Errorf("could not get exam collection, err:%v", err)
	}

	c := New(collection)
	examId := "65477da7b8227e968660aefd"
	simId := testSimulationStorer_Create(t, c, examId)
	testSimulationStorer_GetExamSimulations(t, c, examId)
	testSimulationStorer_Update(t, c, simId, examId)
	testSimulationStorer_Get(t, c, simId)
}

func testSimulationStorer_Create(t *testing.T, s SimulationStorer, examId string) string {
	sim := models.Simulation{}
	err := json.Unmarshal([]byte(simulation_test), &sim)
	if err != nil {
		t.Error(err)
	}

	res, err1 := s.Create(examId, sim)
	if err != nil {
		t.Error(err1)
	}

	assert.Contains(t, res, "InsertedID")

	resultJson := result{}
	err2 := json.Unmarshal([]byte(res), &resultJson)
	if err2 != nil {
		t.Error(err2)
	}

	return resultJson.InsertedId
}

func testSimulationStorer_GetExamSimulations(t *testing.T, s SimulationStorer, examId string) {
	sims, err1 := s.GetExamSimulations(examId)
	if err1 != nil {
		t.Error(err1)
	}
	sim := sims[len(sims)-1]

	expected := models.Simulation{}
	err := json.Unmarshal([]byte(simulation_test), &expected)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, sim.Problems, expected.Problems)
}

func testSimulationStorer_Get(t *testing.T, s SimulationStorer, simulationId string) {
	sims, err1 := s.Get(simulationId)
	if err1 != nil {
		t.Error(err1)
	}
	sim := sims[len(sims)-1]

	expected := models.Simulation{}
	err := json.Unmarshal([]byte(simulation_test), &expected)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, sim.Problems, expected.Problems)
}

func testSimulationStorer_Update(t *testing.T, s SimulationStorer, simId string, examId string) {
	sims, err := s.GetExamSimulations(examId)
	if err != nil {
		t.Error(err)
	}
	idObject, err1 := primitive.ObjectIDFromHex(simId)
	if err1 != nil {
		t.Error(err1)
	}

	var simus []models.Simulation
	for _, v := range sims {
		if v.ID == idObject {
			simus = append(simus, v)
			break
		}
	}

	sim := simus[len(simus)-1]

	sim.StartedAt = time.Now()

	res, err3 := s.Update(simId, sim)
	if err3 != nil {
		t.Error(err3)
	}

	assert.Contains(t, res, "\"MatchedCount\":1,\"ModifiedCount\":1")
}
