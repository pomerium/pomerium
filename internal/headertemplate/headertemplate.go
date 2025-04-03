// Package headertemplate contains functions for rendering header templates.
package headertemplate

import "strings"

// Render renders a header template string.
func Render(src string, fn func(ref []string) string) string {
	p := newParser(src, fn)
	return p.parse()
}

type parser struct {
	buffer []byte
	pos    int
	stack  []int
	visit  func(ref []string) string
}

func newParser(src string, visit func(ref []string) string) *parser {
	return &parser{buffer: []byte(src), visit: visit}
}

func (p *parser) save() {
	p.stack = append(p.stack, p.pos)
}

func (p *parser) restore() {
	p.pos = p.stack[len(p.stack)-1]
}

func (p *parser) pop() {
	p.stack = p.stack[:len(p.stack)-1]
}

func (p *parser) peek() byte {
	if p.pos < len(p.buffer) {
		return p.buffer[p.pos]
	}
	return 0
}

func (p *parser) next() byte {
	if p.pos < len(p.buffer) {
		c := p.buffer[p.pos]
		p.pos++
		return c
	}
	return 0
}

func (p *parser) parse() string {
	var b strings.Builder
	for p.pos < len(p.buffer) {
		if v, ok := p.parseVariable(); ok {
			b.WriteString(v)
			continue
		}
		b.WriteByte(p.next())
	}
	return b.String()
}

func (p *parser) parseVariable() (string, bool) {
	if p.peek() != '$' {
		return "", false
	}

	p.save()
	defer p.pop()

	// $$ becomes $
	p.next()
	if p.peek() == '$' {
		p.next()
		return "$", true
	}

	if p.peek() == '{' {
		p.next()
		e, ok := p.parseComplexExpression()
		if !ok {
			p.restore()
			return "", false
		}
		if p.next() != '}' {
			p.restore()
			return "", false
		}
		return e, true
	}

	e, ok := p.parseSimpleExpression()
	if !ok {
		p.restore()
		return "", false
	}

	return e, true
}

func (p *parser) parseComplexExpression() (string, bool) {
	p.save()
	defer p.pop()

	p.skipWhitespace()

	var ref []string
	id, ok := p.parseIdentifier()
	if !ok {
		p.restore()
		return "", false
	}
	ref = append(ref, id)

	for {
		p.skipWhitespace()

		if p.peek() == '.' {
			p.next()
			p.skipWhitespace()

			id, ok := p.parseIdentifier()
			if !ok {
				p.restore()
				return "", false
			}
			ref = append(ref, id)

		} else if p.peek() == '[' {
			p.next()
			p.skipWhitespace()

			s, ok := p.parseString()
			if !ok {
				p.restore()
				return "", false
			}
			ref = append(ref, s)

			p.skipWhitespace()
			if p.next() != ']' {
				p.restore()
				return "", false
			}
		} else {
			break
		}
	}

	return p.visit(ref), true
}

func (p *parser) parseString() (string, bool) {
	p.save()
	defer p.pop()

	if p.next() != '"' {
		p.restore()
		return "", false
	}

	var b strings.Builder
	for {
		c := p.next()
		switch c {
		case '"':
			return b.String(), true
		case 0:
			p.restore()
			return "", false
		case '\\':
			c = p.next()
			if c == 0 {
				p.restore()
				return "", false
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
}

func (p *parser) parseSimpleExpression() (string, bool) {
	p.save()
	defer p.pop()

	var ref []string
	for {
		id, ok := p.parseIdentifier()
		if !ok {
			p.restore()
			return "", false
		}
		ref = append(ref, id)

		if p.peek() != '.' {
			break
		}
		p.next()
	}

	return p.visit(ref), true
}

func (p *parser) parseIdentifier() (string, bool) {
	p.save()
	defer p.pop()

	var b strings.Builder
	for isIdentifierCharacter(p.peek()) {
		b.WriteByte(p.next())
	}

	if b.Len() == 0 {
		p.restore()
		return "", false
	}

	return b.String(), true
}

func (p *parser) skipWhitespace() {
	for isWhitespaceCharacter(p.peek()) {
		p.next()
	}
}

func isIdentifierCharacter(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		c == '_' ||
		c == '-'
}

func isWhitespaceCharacter(c byte) bool {
	return c == ' ' || c == '\t'
}
