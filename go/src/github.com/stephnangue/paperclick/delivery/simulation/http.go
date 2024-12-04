package simulation

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/stephnangue/paperclick/datastore/certification"
	"github.com/stephnangue/paperclick/datastore/simulation"
	"github.com/stephnangue/paperclick/models"
)

type SimulationHandler struct {
	simulationDatastore    simulation.Simulation
	certificationDatastore certification.Certification
}

func NewSimulationHandler(simulationDatastore simulation.Simulation, certificationDatastore certification.Certification) SimulationHandler {
	return SimulationHandler{simulationDatastore: simulationDatastore, certificationDatastore: certificationDatastore}
}

// GET /v1/simulations/:simulationId
func (h SimulationHandler) Get(c *gin.Context) {
	id := c.Param("simulationId")
	sim, err := h.simulationDatastore.Get(id)
	if err != nil {
		log.Println(err)
		c.String(http.StatusInternalServerError, err.Error())
	} else if len(sim) == 0 {
		c.String(http.StatusNotFound, "there is no simulation with that ID")
	} else {
		c.JSON(http.StatusOK, gin.H{
			"result": sim,
		})
	}
}

// GET /v1/simulations?examId=examId
func (h SimulationHandler) GetExamSimulations(c *gin.Context) {
	examId := c.Query("examId")
	if examId == "" {
		c.String(http.StatusBadRequest, "you should provide the exam ID")
	} else {
		sim, err := h.simulationDatastore.GetExamSimulations(examId)
		if err != nil {
			log.Println(err)
			c.String(http.StatusInternalServerError, err.Error())
		} else {
			c.JSON(http.StatusOK, gin.H{
				"result": sim,
			})
		}
	}
}

// POST /v1/simulation?examId=examId
func (h SimulationHandler) Create(c *gin.Context) {
	examId := c.Query("examId")
	if examId == "" {
		c.String(http.StatusBadRequest, "you should provide the exam ID")
	} else {
		exams, err := h.certificationDatastore.GetExam(examId)
		if err != nil {
			log.Println(err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		if len(exams) == 0 {
			log.Printf("there are no exam with id %v", examId)
			c.String(http.StatusBadRequest, "there are no exam with that id")
			return
		}
		simu, err := GenerateSimulation(exams[len(exams)-1])
		if err != nil {
			log.Println(err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		res, err := h.simulationDatastore.Create(examId, simu)
		if err != nil {
			log.Println(err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"result": res,
		})
	}
}

// PUT /v1/simulations/:simulationId?examId=examId
func (h SimulationHandler) Update(c *gin.Context) {
	examId := c.Query("examId")
	if examId == "" {
		c.String(http.StatusBadRequest, "you should provide the exam ID")
		return
	} else {
		var simu models.Simulation
		if err := c.BindJSON(&simu); err == nil {
			result, err := h.simulationDatastore.Update(examId, simu)
			if err == nil {
				c.JSON(http.StatusOK, gin.H{
					"result": result,
				})
				return
			} else {
				log.Println(err)
				c.String(http.StatusInternalServerError, err.Error())
				return
			}
		} else {
			log.Println(err)
			c.String(http.StatusInternalServerError, err.Error())
		}
	}
}
