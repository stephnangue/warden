package simulation

import "github.com/stephnangue/paperclick/models"

type Simulation interface {
	GetExamSimulations(examId string) ([]models.Simulation, error)
	Get(simulationId string) ([]models.Simulation, error)
	Create(string, models.Simulation) (string, error)
	Update(string, models.Simulation) (string, error)
}
