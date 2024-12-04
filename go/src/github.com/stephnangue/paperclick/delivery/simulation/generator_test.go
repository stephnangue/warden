package simulation

import (
	"testing"

	generator "github.com/stephnangue/paperclick/delivery/certification"
	"github.com/stephnangue/paperclick/models"
	"github.com/stephnangue/paperclick/testdata"
	"github.com/stretchr/testify/assert"
)

func TestGenerateSimulation(t *testing.T) {
	q1 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 20},
		QuestionQuantity: 50,
	}
	q2 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 17},
		QuestionQuantity: 50,
	}
	certi := testdata.GenerateCertification("CERT", 1, 37, []testdata.QuestionsPerDomain{q1, q2})

	exams, err := generator.GenerateExams(certi.ExamQuantity, certi)
	if err != nil {
		t.Error(err)
	}

	exam := exams[len(exams)-1]
	exam.ID = "65495197be3022fd70d7e47c"

	sim, err1 := GenerateSimulation(exam)
	if err != nil {
		t.Log(err)
	}
	assert.Equal(t, len(sim.Problems), 37)
	assert.Equal(t, sim.ExamID, exam.ID)

	sim2, err := GenerateSimulation(exam)
	if err1 != nil {
		t.Log(err)
	}

	assert.NotEqual(t, sim, sim2)

}
