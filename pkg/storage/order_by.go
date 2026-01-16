package storage

import "strings"

type OrderByItem struct {
	Field     string
	Ascending bool
}

func (item OrderByItem) String() string {
	if item.Ascending {
		return item.Field
	}
	return "-" + item.Field
}

type OrderBy []OrderByItem

func OrderByFromString(str string) OrderBy {
	var orderBy OrderBy
	for s := range strings.SplitSeq(str, ",") {
		item := OrderByItem{
			Field:     strings.TrimSpace(s),
			Ascending: true,
		}
		if strings.HasPrefix(item.Field, "-") {
			item.Ascending = false
			item.Field = item.Field[1:]
			item.Field = strings.TrimSpace(item.Field)
		}
		if item.Field != "" {
			orderBy = append(orderBy, item)
		}
	}
	return orderBy
}

func (orderBy OrderBy) String() string {
	var sb strings.Builder
	for i, item := range orderBy {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(item.String())
	}
	return sb.String()
}
