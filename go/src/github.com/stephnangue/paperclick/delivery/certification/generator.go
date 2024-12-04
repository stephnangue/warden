package certification

import (
	"fmt"
	"math/rand"

	"github.com/stephnangue/paperclick/models"
)

func GenerateExams(quantity int, certification models.Certification) ([]models.Exam, error) {
	var exams []models.Exam
	// Declare a map that will contain a pool of question per domain
	var questionsPool = make(map[int][]models.Question)

	// Fill the pools of questions
	for j, l := range certification.Domains {
		questionsPool[j] = l.Questions
	}

	for i := 0; i < quantity; i++ {
		var quizzes []models.Quiz

		for k, v := range certification.Domains {
			if len(v.Questions) <= 0 {
				return nil, fmt.Errorf("the domain \"%v\" has no questions", v.Name)
			}
			var questionQuantity = v.QuestionQuantity
			if questionQuantity < 0 {
				return nil, fmt.Errorf("the number of questions (%v) should be positive", questionQuantity)
			}
			if len(v.Questions) < questionQuantity {
				return nil, fmt.Errorf("the number of questions (%v) should not be greater than number of questions available (%v) for the domain \"%v\"", questionQuantity, len(v.Questions), v.Name)
			}
			// Get the pool of questions for that domain
			question := questionsPool[k]
			// Shuffle the pool
			rand.Shuffle(len(question), func(i, j int) {
				question[i], question[j] = question[j], question[i]
			})
			// Extract from that pool the mandatory quantity of questions for the domain
			var part []models.Question
			if questionQuantity <= len(question) {
				part = question[:questionQuantity]
			} else {
				part = append(part, question...)
				questionQuantity = questionQuantity - len(question)
				refill(k, questionsPool, certification.Domains)
				question = questionsPool[k]
				rand.Shuffle(len(question), func(i, j int) {
					question[i], question[j] = question[j], question[i]
				})
				part = append(part, question[:questionQuantity]...)
			}

			// Create Quizzes from the extracted questions
			for _, q := range part {
				quizzes = append(quizzes, models.Quiz{
					Domain:               v.Name,
					Stem:                 q.Stem,
					Explanation:          q.Explanation,
					PartialAnswerAllowed: q.PartialAnswerAllowed,
					Answers:              q.Answers,
				})
			}
			// Remove the extacted questions from the pool
			questionsPool[k] = question[questionQuantity:]
		}
		exam := models.Exam{
			Quizzes: quizzes,
		}
		exams = append(exams, exam)
	}
	return exams, nil
}

func refill(index int, pool map[int][]models.Question, domains []models.Domain) {
	for i, v := range domains {
		if index == i {
			pool[i] = v.Questions
			break
		}
	}
}
