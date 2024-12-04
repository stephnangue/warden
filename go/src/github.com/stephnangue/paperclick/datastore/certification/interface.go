package certification

import "github.com/stephnangue/paperclick/models"

type Certification interface {
	Get(certificationCode string) ([]models.Certification, error)
	GetExams(certificationCode string) ([]models.Exam, error)
	GetExam(examId string) ([]models.Exam, error)
	Create(models.Certification) (string, error)
	CreateExams(string, []models.Exam) (string, error)
}
