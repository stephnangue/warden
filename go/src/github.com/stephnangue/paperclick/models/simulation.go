package models

import "time"

type Problem struct {
	Domain               string   `json:"domain" bson:"domain"`
	Stem                 string   `json:"stem" bson:"stem"`
	Explanation          string   `json:"explanation" bson:"explanation"`
	PartialAnswerAllowed bool     `json:"partialAnswerAllowed" bson:"partialAnswerAllowed"`
	Displayed            bool     `json:"displayed" bson:"displayed"`
	Choices              []Choice `json:"answers" bson:"answers"`
}

type Choice struct {
	Statement string  `json:"statement" bson:"statement"`
	IsCorrect bool    `json:"isCorrect" bson:"isCorrect"`
	Score     float64 `json:"score" bson:"score"`
	Selected  bool    `json:"selected" bson:"selected"`
}

type Simulation struct {
	ID        interface{} `json:"id" bson:"_id,omitempty"`
	ExamID    interface{} `json:"examId" bson:"examId,omitempty"`
	StartedAt time.Time   `json:"startedAt" bson:"startedAt"`
	EndedAt   time.Time   `json:"endedAt" bson:"endedAt"`
	Problems  []Problem   `json:"questions" bson:"questions"`
}
