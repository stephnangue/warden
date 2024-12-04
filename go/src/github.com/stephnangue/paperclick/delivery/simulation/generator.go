package simulation

import (
	"math/rand"

	"github.com/stephnangue/paperclick/models"
)

func GenerateSimulation(exam models.Exam) (models.Simulation, error) {
	var problems []models.Problem
	quizzes := exam.Quizzes
	rand.Shuffle(len(quizzes), func(i, j int) {
		quizzes[i], quizzes[j] = quizzes[j], quizzes[i]
	})
	for _, q := range quizzes {
		problem := models.Problem{
			Domain:               q.Domain,
			Stem:                 q.Stem,
			Explanation:          q.Explanation,
			PartialAnswerAllowed: q.PartialAnswerAllowed,
			Displayed:            false,
		}
		answers := q.Answers
		rand.Shuffle(len(answers), func(i, j int) {
			answers[i], answers[j] = answers[j], answers[i]
		})
		choices := []models.Choice{}
		for _, a := range answers {
			choice := models.Choice{
				Statement: a.Statement,
				IsCorrect: a.IsCorrect,
				Score:     float64(a.Score),
				Selected:  false,
			}
			choices = append(choices, choice)
		}
		problem.Choices = choices
		problems = append(problems, problem)
	}
	simulation := models.Simulation{
		ExamID:   exam.ID,
		Problems: problems,
	}
	return simulation, nil
}
