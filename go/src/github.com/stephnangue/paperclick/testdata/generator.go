package testdata

import (
	"github.com/brianvoe/gofakeit/v6"
	"github.com/stephnangue/paperclick/models"
)

type QuestionsPerDomain struct {
	Domain           models.Domain
	QuestionQuantity int
}

func GenerateCertification(code string, examQuantity int, questionsPerExam int, questionsPerDomain []QuestionsPerDomain) models.Certification {
	exams := []models.Exam{}
	domainList := []models.Domain{}
	for _, v := range questionsPerDomain {
		v.Domain.Questions = generateQuestions(v.QuestionQuantity)
		domainList = append(domainList, v.Domain)
	}
	cert := models.Certification{
		Code:             code,
		Name:             gofakeit.MovieName(),
		Description:      gofakeit.Paragraph(1, 4, 20, "/n"),
		QuestionQuantity: questionsPerExam,
		Duration:         gofakeit.RandomInt([]int{60, 120, 180}),
		PassingScore:     gofakeit.RandomInt([]int{500, 600, 720, 800}),
		ExamQuantity:     examQuantity,
		Domains:          domainList,
		Exams:            exams,
	}
	return cert
}

func generateQuestions(quantity int) []models.Question {
	var questions []models.Question
	for i := 0; i < quantity; i++ {
		answersCount := gofakeit.RandomInt([]int{4, 5, 6})
		question := models.Question{
			Stem:                 gofakeit.Sentence(30),
			Explanation:          gofakeit.Sentence(45),
			PartialAnswerAllowed: gofakeit.Bool(),
			Answers:              generateAnswers(answersCount),
		}
		questions = append(questions, question)
	}
	return questions
}

func generateAnswers(quantity int) []models.Answer {
	var answers []models.Answer
	for i := 0; i < quantity; i++ {
		correct := gofakeit.Bool()
		score := 0
		if correct {
			score = 15
		}
		answer := models.Answer{
			Statement: gofakeit.SentenceSimple(),
			IsCorrect: correct,
			Score:     score,
		}
		answers = append(answers, answer)
	}
	return answers
}
