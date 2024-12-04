package certification

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stephnangue/paperclick/driver"
	"github.com/stephnangue/paperclick/models"
	"github.com/stephnangue/paperclick/testdata"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const cert_test = `
{
	"code": "AWS-SSA-C03",
	"name": "AWS Solution Architect Associate",
	"description": "AWS Solution Architect Associate",
	"questionQuantity": 65,
	"duration": 130,
	"passingScore": 720,
	"examQuantity": 2,
	"domains": [
		{
			"name": "Design Secure Architectures",
			"questionQuantity": 18,
			"questions": [
				{
					"stem": "A company runs a public-facing three-tier web application in a VPC across multiple Availability Zones.",
					"explanation": "A NAT gateway forwards traffic from the EC2 instances in the private subnet to the internet",
					"partialAnswerAllowed": false,
					"answers": [
						{
							"statement": "Configure a NAT gateway in a public subnet.",
							"isCorrect": true,
							"score": 10
						},
						{
							"statement": "Define a custom route table with a route to the NAT gateway for internet traffic and associate it with the private subnets for the application tier.",
							"isCorrect": true,
							"score": 10
						},
						{
							"statement": "Assign Elastic IP addresses to the EC2 instances.",
							"isCorrect": false,
							"score": 0
						},
						{
							"statement": "Define a custom route table with a route to the internet gateway for internet traffic and associate it with the private subnets for the application tier.",
							"isCorrect": false,
							"score": 0
						},
						{
							"statement": "Configure a NAT instance in a private subnet.",
							"isCorrect": false,
							"score": 0
						}
					]
				}
			]
		}
	],
	"exams": []
}
`
const exam_test = `
{
    "questions": [
        {
            "domain": "Design Secure Architectures",
            "stem": "A company runs a public-facing three-tier web application in a VPC across multiple Availability Zones.",
            "explanation": "A NAT gateway forwards traffic from the EC2 instances in the private subnet to the internet",
            "partialAnswerAllowed": false,
            "answers": [
                {
                    "statement": "Configure a NAT gateway in a public subnet.",
                    "isCorrect": true,
                    "score": 10
                },
                {
                    "statement": "Define a custom route table with a route to the NAT gateway for internet traffic and associate it with the private subnets for the application tier.",
                    "isCorrect": true,
                    "score": 10
                },
                {
                    "statement": "Assign Elastic IP addresses to the EC2 instances.",
                    "isCorrect": false,
                    "score": 0
                },
                {
                    "statement": "Define a custom route table with a route to the internet gateway for internet traffic and associate it with the private subnets for the application tier.",
                    "isCorrect": false,
                    "score": 0
                },
                {
                    "statement": "Configure a NAT instance in a private subnet.",
                    "isCorrect": false,
                    "score": 0
                }
            ]
        }
    ]
}
`

const default_code = "AWS-SSA-C03"

func TestDatastore(t *testing.T) {
	code := generateRandomString(10)
	collection, err := driver.GetCollection("paper", "certifications")
	if err != nil {
		t.Errorf("could not get certification collection, err:%v", err)
	}
	c := New(collection)
	certificationCode := default_code + code
	testCertificationStorer_Create(t, c, certificationCode)
	testCertificationStorer_Get(t, c, certificationCode)
	testCertificationStorer_CreateExams(t, c, certificationCode)
	testCertificationStorer_GetExams(t, c, certificationCode)
	testCertificationStorer_GetExam(t, c)
	newCertification(t, c)
}

func testCertificationStorer_Create(t *testing.T, c CertificationStorer, code string) {
	cert := models.Certification{}
	err := json.Unmarshal([]byte(cert_test), &cert)
	if err != nil {
		t.Error(err)
	}
	cert.Code = code

	id, err1 := c.Create(cert)
	if err1 != nil {
		t.Error(err1)
	}

	assert.Contains(t, id, "InsertedID")
}

func testCertificationStorer_Get(t *testing.T, c CertificationStorer, code string) {
	certis, err1 := c.Get(code)
	if err1 != nil {
		t.Error(err1)
	}
	certi := certis[len(certis)-1]

	cert := models.Certification{}
	err := json.Unmarshal([]byte(cert_test), &cert)
	if err != nil {
		t.Error(err)
	}
	cert.Code = code

	assert.Equal(t, certi.Domains, cert.Domains)
}

func testCertificationStorer_CreateExams(t *testing.T, c CertificationStorer, code string) {
	exam := models.Exam{}
	err := json.Unmarshal([]byte(exam_test), &exam)
	if err != nil {
		t.Error(err)
	}
	var exams []models.Exam
	exams = append(exams, exam)
	exams = append(exams, exam)

	result, err1 := c.CreateExams(code, exams)
	if err1 != nil {
		t.Error(err1)
	}

	assert.Contains(t, result, "{\"MatchedCount\":1,\"ModifiedCount\":1")
}

func testCertificationStorer_GetExams(t *testing.T, c CertificationStorer, code string) {
	exams, err := c.GetExams(code)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, len(exams), 2)
}

func testCertificationStorer_GetExam(t *testing.T, c CertificationStorer) {
	id := "65495197be3022fd70d7e47c"
	idObject, err1 := primitive.ObjectIDFromHex(id)
	if err1 != nil {
		panic(err1)
	}
	exams, err := c.GetExam(id)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, len(exams), 1)
	assert.Equal(t, exams[len(exams)-1].ID, idObject)
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func newCertification(t *testing.T, c CertificationStorer) {
	q1 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Design Secure Architectures", QuestionQuantity: 20},
		QuestionQuantity: 50,
	}
	q2 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Design Resilient Architectures", QuestionQuantity: 17},
		QuestionQuantity: 50,
	}
	q3 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Design High-Performing Architectures", QuestionQuantity: 15},
		QuestionQuantity: 50,
	}
	q4 := testdata.QuestionsPerDomain{
		Domain:           models.Domain{Name: "Design Cost-Optimized Architectures", QuestionQuantity: 13},
		QuestionQuantity: 50,
	}

	certification := testdata.GenerateCertification("SAA-C03-V3", 4, 65, []testdata.QuestionsPerDomain{q1, q2, q3, q4})

	id, err1 := c.Create(certification)
	if err1 != nil {
		t.Error(err1)
	}

	assert.Contains(t, id, "InsertedID")

}
