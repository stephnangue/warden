package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/stephnangue/paperclick/datastore/certification"
	"github.com/stephnangue/paperclick/datastore/simulation"
	handerCertification "github.com/stephnangue/paperclick/delivery/certification"
	handerSimulation "github.com/stephnangue/paperclick/delivery/simulation"
	"github.com/stephnangue/paperclick/driver"
)

func main() {
	certCollection, err := driver.GetCollection("paper", "certifications")
	if err != nil {
		log.Println("could not get certification collection, err:", err)
		return
	}
	simCollection, err := driver.GetCollection("paper", "simulations")
	if err != nil {
		log.Println("could not get simulation collection, err:", err)
		return
	}

	certStore := certification.New(certCollection)
	simStore := simulation.New(simCollection)

	certHandler := handerCertification.NewCertificationHandler(certStore)
	simtHandler := handerSimulation.NewSimulationHandler(simStore, certStore)

	router := gin.Default()

	router.POST("/v1/certification", certHandler.Create)
	router.GET("/v1/certifications/:code", certHandler.Get)
	router.GET("/v1/certifications/:code/exams", certHandler.GetExams)
	router.PATCH("/v1/certifications/:code/exams", certHandler.CreateExams)
	router.GET("/v1/simulations/:simulationId", simtHandler.Get)
	router.GET("/v1/simulations", simtHandler.GetExamSimulations)
	router.POST("/v1/simulation", simtHandler.Create)
	router.PUT("/v1/simulations/:simulationId", simtHandler.Update)

	router.Run(":8000")
}
