package models

type Certification struct {
	ID               interface{} `json:"id" bson:"_id,omitempty"`
	Code             string      `json:"code" bson:"code"`
	Name             string      `json:"name" bson:"name"`
	Description      string      `json:"description" bson:"description"`
	QuestionQuantity int         `json:"questionQuantity" bson:"questionQuantity"`
	Duration         int         `json:"duration" bson:"duration"`
	PassingScore     int         `json:"passingScore" bson:"passingScore"`
	ExamQuantity     int         `json:"examQuantity" bson:"examQuantity"`
	Domains          []Domain    `json:"domains" bson:"domains"`
	Exams            []Exam      `json:"exams" bson:"exams"`
}

type Domain struct {
	Name             string     `json:"name" bson:"name"`
	QuestionQuantity int        `json:"questionQuantity" bson:"questionQuantity"`
	Questions        []Question `json:"questions" bson:"questions"`
}

type Question struct {
	Stem                 string   `json:"stem" bson:"stem"`
	Explanation          string   `json:"explanation" bson:"explanation"`
	PartialAnswerAllowed bool     `json:"partialAnswerAllowed" bson:"partialAnswerAllowed"`
	Answers              []Answer `json:"answers" bson:"answers"`
}

type Answer struct {
	Statement string `json:"statement" bson:"statement"`
	IsCorrect bool   `json:"isCorrect" bson:"isCorrect"`
	Score     int    `json:"score" bson:"score"`
}

type Exam struct {
	ID      interface{} `json:"id" bson:"_id,omitempty"`
	Quizzes []Quiz      `json:"questions" bson:"questions"`
}

type Quiz struct {
	Domain               string   `json:"domain" bson:"domain"`
	Stem                 string   `json:"stem" bson:"stem"`
	Explanation          string   `json:"explanation" bson:"explanation"`
	PartialAnswerAllowed bool     `json:"partialAnswerAllowed" bson:"partialAnswerAllowed"`
	Answers              []Answer `json:"answers" bson:"answers"`
}
