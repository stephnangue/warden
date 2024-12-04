package certification

import (
	"testing"

	"github.com/stephnangue/paperclick/models"
	"github.com/stephnangue/paperclick/testdata"
	"github.com/stretchr/testify/assert"
)

func TestGenerateExams(t *testing.T) {
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
		t.Error(err)
	}

	assert.Equal(t, len(exams), 1)
	for _, e := range exams {
		assert.Equal(t, len(e.Quizzes), 37)
	}

	certi = testdata.GenerateCertification("CERT", 2, 37, []testdata.QuestionsPerDomain{q1, q2})

	exams, err = GenerateExams(certi.ExamQuantity, certi)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, len(exams), 2)
	for _, e := range exams {
		assert.Equal(t, len(e.Quizzes), 37)
	}

	q1 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 100},
		QuestionQuantity: 50,
	}
	q2 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 67},
		QuestionQuantity: 50,
	}

	certi = testdata.GenerateCertification("CERT", 2, 167, []testdata.QuestionsPerDomain{q1, q2})

	_, err = GenerateExams(certi.ExamQuantity, certi)
	assert.EqualError(t, err, "the number of questions (100) should not be greater than number of questions available (50) for the domain \"Domain1\"")

	q1 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 10},
		QuestionQuantity: 50,
	}
	q2 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 7},
		QuestionQuantity: 0,
	}

	certi = testdata.GenerateCertification("CERT", 2, 167, []testdata.QuestionsPerDomain{q1, q2})

	_, err = GenerateExams(certi.ExamQuantity, certi)
	assert.EqualError(t, err, "the domain \"Domain2\" has no questions")

	q1 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 10},
		QuestionQuantity: 50,
	}
	q2 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 0},
		QuestionQuantity: 10,
	}

	certi = testdata.GenerateCertification("CERT", 2, 10, []testdata.QuestionsPerDomain{q1, q2})

	exams, err = GenerateExams(certi.ExamQuantity, certi)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, len(exams), 2)
	for _, e := range exams {
		assert.Equal(t, len(e.Quizzes), 10)
	}

	q1 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain1", QuestionQuantity: 48},
		QuestionQuantity: 50,
	}
	q2 = testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Domain2", QuestionQuantity: 8},
		QuestionQuantity: 10,
	}

	certi = testdata.GenerateCertification("CERT", 20, 56, []testdata.QuestionsPerDomain{q1, q2})

	exams, err = GenerateExams(certi.ExamQuantity, certi)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, len(exams), 20)
	for _, e := range exams {
		assert.Equal(t, len(e.Quizzes), 56)
	}

}
