package logical

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deadlineRecorder is a ResponseWriter that records the deadlines set on it,
// standing in for a real connection. httptest.ResponseRecorder supports
// neither, so it cannot distinguish "cleared" from "never attempted".
type deadlineRecorder struct {
	http.ResponseWriter
	readSet  []time.Time
	writeSet []time.Time
	setErr   error
}

func newDeadlineRecorder() *deadlineRecorder {
	return &deadlineRecorder{ResponseWriter: httptest.NewRecorder()}
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	if d.setErr != nil {
		return d.setErr
	}
	d.readSet = append(d.readSet, t)
	return nil
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	if d.setErr != nil {
		return d.setErr
	}
	d.writeSet = append(d.writeSet, t)
	return nil
}

func TestClearStreamDeadlines_ClearsBoth(t *testing.T) {
	rec := newDeadlineRecorder()

	require.NoError(t, ClearStreamDeadlines(rec))

	require.Len(t, rec.readSet, 1, "the read deadline governs a slow upload and must be cleared too")
	require.Len(t, rec.writeSet, 1)
	assert.True(t, rec.readSet[0].IsZero())
	assert.True(t, rec.writeSet[0].IsZero())
}

// A writer with no connection behind it has no deadline to shed, so
// ErrNotSupported is not a failure — httptest.ResponseRecorder takes this
// path throughout the test suite.
func TestClearStreamDeadlines_UnsupportedIsNotAnError(t *testing.T) {
	assert.NoError(t, ClearStreamDeadlines(httptest.NewRecorder()))
	assert.NoError(t, ClearStreamDeadlines(nil))
}

func TestClearStreamDeadlines_ReportsRealErrors(t *testing.T) {
	rec := newDeadlineRecorder()
	rec.setErr = errors.New("connection gone")

	assert.ErrorContains(t, ClearStreamDeadlines(rec), "connection gone")
}

// ClearStreamDeadlines must see through the wrapper the HTTP layer puts on
// every request's writer, or the clear would silently reach nothing.
func TestClearStreamDeadlines_ThroughStatusRecordingWriter(t *testing.T) {
	rec := newDeadlineRecorder()

	require.NoError(t, ClearStreamDeadlines(NewStatusRecordingWriter(rec)))

	assert.Len(t, rec.readSet, 1)
	assert.Len(t, rec.writeSet, 1)
}

// Clearing the write deadline alone is what a caller with an unread request
// body wants: the response is uncapped while a dribbling client stays bounded
// by the read deadline the listener armed.
func TestClearStreamWriteDeadline_LeavesTheReadDeadlineArmed(t *testing.T) {
	rec := newDeadlineRecorder()

	require.NoError(t, ClearStreamWriteDeadline(rec))

	require.Len(t, rec.writeSet, 1)
	assert.True(t, rec.writeSet[0].IsZero())
	assert.Empty(t, rec.readSet, "the body has not been read yet; its bound must stay")
}

func TestSetStreamReadDeadline(t *testing.T) {
	rec := newDeadlineRecorder()
	window := time.Now().Add(time.Minute)

	require.NoError(t, SetStreamReadDeadline(rec, window))
	require.NoError(t, SetStreamReadDeadline(rec, time.Time{}))

	require.Len(t, rec.readSet, 2)
	assert.Equal(t, window, rec.readSet[0])
	assert.True(t, rec.readSet[1].IsZero(), "the zero time removes the deadline")
	assert.Empty(t, rec.writeSet)
}

func TestSetStreamReadDeadline_UnsupportedIsNotAnError(t *testing.T) {
	assert.NoError(t, SetStreamReadDeadline(httptest.NewRecorder(), time.Now()))
	assert.NoError(t, SetStreamReadDeadline(nil, time.Now()))
	assert.NoError(t, ClearStreamWriteDeadline(nil))
}
