package certification

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/stephnangue/paperclick/datastore/certification"
	"github.com/stephnangue/paperclick/models"
)

type CertificationHandler struct {
	datastore certification.Certification
}

func NewCertificationHandler(datastore certification.Certification) CertificationHandler {
	return CertificationHandler{datastore: datastore}
}

func (h CertificationHandler) Get(c *gin.Context) {
	code := c.Param("code")
	certi, err := h.datastore.Get(code)
	if err != nil {
		log.Println(err)
		c.String(http.StatusInternalServerError, err.Error())
	} else {
		certi[len(certi)-1].Exams = []models.Exam{}
		withQuestions := c.Query("withQuestions")
		if withQuestions != "true" {
			certi[len(certi)-1].Domains = []models.Domain{}
		}
		c.JSON(http.StatusOK, gin.H{
			"result": certi,
		})
	}
}

func (h CertificationHandler) Create(c *gin.Context) {
	var certi models.Certification
	if err := c.BindJSON(&certi); err == nil {
		result, err := h.datastore.Create(certi)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"result": result,
			})
		} else {
			c.String(http.StatusInternalServerError, err.Error())
		}
	} else {
		c.String(http.StatusInternalServerError, err.Error())
	}
}

func (h CertificationHandler) GetExams(c *gin.Context) {
	code := c.Param("code")
	exams, err := h.datastore.GetExams(code)
	if err != nil {
		log.Println(err)
		c.String(http.StatusInternalServerError, err.Error())
	} else {
		c.JSON(http.StatusOK, gin.H{
			"result": exams,
		})
	}
}

func (h CertificationHandler) CreateExams(c *gin.Context) {
	code := c.Param("code")
	certif, err := h.datastore.Get(code)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	} else {
		examQty := len(certif[len(certif)-1].Exams)
		if examQty > 0 {
			c.String(http.StatusBadRequest, fmt.Sprintf("the certification with code %v already contains %d exam(s)", code, examQty))
		} else {
			exams, err := GenerateExams(certif[len(certif)-1].ExamQuantity, certif[len(certif)-1])
			if err != nil {
				c.String(http.StatusInternalServerError, err.Error())
			} else {
				result, err := h.datastore.CreateExams(code, exams)
				if err != nil {
					c.String(http.StatusInternalServerError, err.Error())
				} else {
					c.JSON(http.StatusOK, gin.H{
						"result": result,
					})
				}
			}
		}
	}
}
