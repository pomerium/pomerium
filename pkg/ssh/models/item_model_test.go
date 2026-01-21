package models_test

import (
	"slices"
	"testing"

	"github.com/pomerium/pomerium/pkg/ssh/models"
	mock_models "github.com/pomerium/pomerium/pkg/ssh/models/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type TestData struct {
	ID  int
	Str string
}

func (td TestData) Key() int {
	return td.ID
}

func TestItemModel_Empty(t *testing.T) {
	m := models.NewItemModel[TestData]()
	{
		idx := m.Index(0)
		assert.Equal(t, m.End(), idx)
		assert.False(t, idx.IsValid(m))
	}

	assert.Equal(t, TestData{}, m.Find(0))

	assert.Panics(t, func() {
		m.Delete(models.Index(0))
	})

	assert.Equal(t, models.Index(0), m.End())
}

func TestItemModel_Append(t *testing.T) {
	ctrl := gomock.NewController(t)

	listener := mock_models.NewMockItemModelListener[TestData](ctrl)
	removedListener := mock_models.NewMockItemModelListener[TestData](ctrl)
	m := models.NewItemModel[TestData]()
	m.AddListener(listener)
	m.AddListener(removedListener)
	m.RemoveListener(removedListener)
	assert.Equal(t, []models.ItemModelListener[TestData, int]{listener}, slices.Collect(m.Listeners()))

	one := TestData{ID: 1, Str: "one"}
	two := TestData{ID: 2, Str: "two"}
	three := TestData{ID: 3, Str: "three"}
	listener.EXPECT().OnIndexUpdate(models.Index(0), models.Index(0), []TestData{one})
	m.Put(one)
	listener.EXPECT().OnIndexUpdate(models.Index(1), models.Index(1), []TestData{two})
	m.Put(two)
	listener.EXPECT().OnIndexUpdate(models.Index(2), models.Index(2), []TestData{three})
	m.Put(three)

	assert.Equal(t, models.Index(0), m.Index(1))
	assert.Equal(t, models.Index(1), m.Index(2))
	assert.Equal(t, models.Index(2), m.Index(3))

	assert.True(t, m.Index(1).IsValid(m))
	assert.True(t, m.Index(2).IsValid(m))
	assert.True(t, m.Index(3).IsValid(m))

	assert.Equal(t, one, m.Find(1))
	assert.Equal(t, two, m.Find(2))
	assert.Equal(t, three, m.Find(3))

	listener2 := mock_models.NewMockItemModelListener[TestData](ctrl)
	listener2.EXPECT().OnIndexUpdate(models.Index(0), models.Index(0), []TestData{one, two, three})
	m.AddListener(listener2)
	assert.Equal(t, []models.ItemModelListener[TestData, int]{listener, listener2}, slices.Collect(m.Listeners()))
	m.RemoveListener(listener)
	assert.Equal(t, []models.ItemModelListener[TestData, int]{listener2}, slices.Collect(m.Listeners()))
	m.RemoveListener(listener2)
	assert.Empty(t, slices.Collect(m.Listeners()))
}

func TestItemModel_Replace(t *testing.T) {
	ctrl := gomock.NewController(t)

	listener := mock_models.NewMockItemModelListener[TestData](ctrl)
	m := models.NewItemModel[TestData]()
	m.AddListener(listener)

	one := TestData{ID: 1, Str: "one"}
	two := TestData{ID: 2, Str: "two"}
	three := TestData{ID: 3, Str: "three"}
	listener.EXPECT().OnIndexUpdate(models.Index(0), models.Index(0), []TestData{one})
	m.Put(one)
	listener.EXPECT().OnIndexUpdate(models.Index(1), models.Index(1), []TestData{two})
	m.Put(two)
	listener.EXPECT().OnIndexUpdate(models.Index(2), models.Index(2), []TestData{three})
	m.Put(three)

	four := TestData{ID: two.ID, Str: "four"}
	listener.EXPECT().OnIndexUpdate(models.Index(1), models.Index(2), []TestData{four})
	m.Put(four)

	assert.Equal(t, one, m.Find(1))
	assert.Equal(t, four, m.Find(2))
	assert.Equal(t, three, m.Find(3))

	listener2 := mock_models.NewMockItemModelListener[TestData](ctrl)
	listener2.EXPECT().OnIndexUpdate(models.Index(0), models.Index(0), []TestData{one, four, three})
	m.AddListener(listener2)
}

func TestItemModel_Data(t *testing.T) {
	m := models.NewItemModel[TestData]()

	one := TestData{ID: 1, Str: "one"}
	two := TestData{ID: 2, Str: "two"}
	three := TestData{ID: 3, Str: "three"}
	m.Put(one)
	m.Put(two)
	m.Put(three)

	assert.Equal(t, one, m.Data(m.Index(1)))
	assert.Equal(t, two, m.Data(m.Index(2)))
	assert.Equal(t, three, m.Data(m.Index(3)))
}

func TestItemModel_Delete(t *testing.T) {
	ctrl := gomock.NewController(t)

	listener := mock_models.NewMockItemModelListener[TestData](ctrl)
	m := models.NewItemModel[TestData]()
	m.AddListener(listener)

	one := TestData{ID: 1, Str: "one"}
	two := TestData{ID: 2, Str: "two"}
	three := TestData{ID: 3, Str: "three"}
	listener.EXPECT().OnIndexUpdate(models.Index(0), models.Index(0), []TestData{one})
	m.Put(one)
	listener.EXPECT().OnIndexUpdate(models.Index(1), models.Index(1), []TestData{two})
	m.Put(two)
	listener.EXPECT().OnIndexUpdate(models.Index(2), models.Index(2), []TestData{three})
	m.Put(three)

	listener.EXPECT().OnIndexUpdate(models.Index(0), models.Index(3), []TestData{two, three})
	m.Delete(models.Index(0))

	{
		assert.Equal(t, m.End(), m.Index(1))
		assert.Equal(t, models.Index(0), m.Index(2))
		assert.Equal(t, models.Index(1), m.Index(3))

		assert.Equal(t, TestData{}, m.Find(1))
		assert.Equal(t, two, m.Find(2))
		assert.Equal(t, three, m.Find(3))
	}

	listener.EXPECT().OnIndexUpdate(models.Index(1), models.Index(2), []TestData{})
	m.Delete(models.Index(1))

	{
		assert.Equal(t, m.End(), m.Index(1))
		assert.Equal(t, models.Index(0), m.Index(2))
		assert.Equal(t, m.End(), m.Index(3))

		assert.Equal(t, TestData{}, m.Find(1))
		assert.Equal(t, two, m.Find(2))
		assert.Equal(t, TestData{}, m.Find(3))
	}

	listener.EXPECT().OnIndexUpdate(models.Index(0), models.Index(1), []TestData{})
	m.Delete(models.Index(0))

	{
		assert.Equal(t, m.End(), m.Index(1))
		assert.Equal(t, m.End(), m.Index(2))
		assert.Equal(t, m.End(), m.Index(3))

		assert.Equal(t, TestData{}, m.Find(1))
		assert.Equal(t, TestData{}, m.Find(2))
		assert.Equal(t, TestData{}, m.Find(3))
	}

	listener2 := mock_models.NewMockItemModelListener[TestData](ctrl)
	m.AddListener(listener2) // should get no callbacks
}

func TestItemModel_Reset(t *testing.T) {
	ctrl := gomock.NewController(t)

	listener := mock_models.NewMockItemModelListener[TestData](ctrl)
	m := models.NewItemModel[TestData]()
	m.AddListener(listener)

	one := TestData{ID: 1, Str: "one"}
	two := TestData{ID: 2, Str: "two"}
	three := TestData{ID: 3, Str: "three"}
	listener.EXPECT().OnIndexUpdate(models.Index(0), models.Index(0), []TestData{one})
	m.Put(one)
	listener.EXPECT().OnIndexUpdate(models.Index(1), models.Index(1), []TestData{two})
	m.Put(two)
	listener.EXPECT().OnIndexUpdate(models.Index(2), models.Index(2), []TestData{three})
	m.Put(three)

	four := TestData{ID: one.ID, Str: "four"}
	five := TestData{ID: two.ID, Str: "five"}
	six := TestData{ID: three.ID, Str: "six"}
	listener.EXPECT().OnModelReset([]TestData{four, five, six})
	m.Reset([]TestData{four, five, six})

	{
		assert.Equal(t, models.Index(0), m.Index(1))
		assert.Equal(t, models.Index(1), m.Index(2))
		assert.Equal(t, models.Index(2), m.Index(3))

		assert.Equal(t, four, m.Find(1))
		assert.Equal(t, five, m.Find(2))
		assert.Equal(t, six, m.Find(3))
	}

	seven := TestData{ID: 7, Str: "seven"}
	eight := TestData{ID: 8, Str: "eight"}
	nine := TestData{ID: 9, Str: "nine"}

	listener.EXPECT().OnModelReset([]TestData{seven, eight, nine})
	m.Reset([]TestData{seven, eight, nine})

	{
		assert.Equal(t, m.End(), m.Index(1))
		assert.Equal(t, m.End(), m.Index(2))
		assert.Equal(t, m.End(), m.Index(3))
		assert.Equal(t, models.Index(0), m.Index(7))
		assert.Equal(t, models.Index(1), m.Index(8))
		assert.Equal(t, models.Index(2), m.Index(9))

		assert.Equal(t, seven, m.Find(7))
		assert.Equal(t, eight, m.Find(8))
		assert.Equal(t, nine, m.Find(9))
	}

	listener2 := mock_models.NewMockItemModelListener[TestData](ctrl)
	listener2.EXPECT().OnIndexUpdate(models.Index(0), models.Index(0), []TestData{seven, eight, nine})
	m.AddListener(listener2)

	listener.EXPECT().OnModelReset([]TestData{seven, eight, nine})
	listener2.EXPECT().OnModelReset([]TestData{seven, eight, nine})
	m.InvalidateAll()
}
