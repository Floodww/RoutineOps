//go:build linux

// Package x11ui — общие примитивы рисования текста в X11 для окон, которые агент
// показывает сотруднику: замка блокировки (lockui) и плашки наблюдения за экраном
// (screen).
//
// Пакет заведён не ради красоты, а из-за конкретного класса отказа. Подбор шрифта в X11
// нельзя делать по факту «открылся»: шаблон "-*-*-..." матчит в том числе масштабируемые
// начертания экзотических наборов, которые открываются без ошибки и рисуют строку нулевой
// ширины. Замок на живом Xvfb именно так показывал чёрный экран, считая, что всё
// нарисовал. Две копии этой проверки разъехались бы молча, а цена расхождения — окно без
// текста у сотрудника, то есть ровно тот исход, который мы и защищаем.
package x11ui

import (
	"log/slog"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
)

// Fonts — подобранная пара шрифтов и признак того, доступен ли двухбайтовый вывод.
//
// TwoByte=false означает, что ни одного Unicode-шрифта с настоящей кириллицей на машине
// нет и текст придётся показывать латиницей. Показать латиницу честнее, чем ряд пустых
// квадратов: сотрудник должен понять, что происходит с его машиной.
type Fonts struct {
	Big     xproto.Font
	Text    xproto.Font
	TwoByte bool

	BigName  string
	TextName string
}

// Candidate — шаблон шрифта и ожидаемый размер в пикселях.
type Candidate struct {
	Pattern string
	Pixel   int
}

// BigCandidates — кандидаты под заголовок.
//
// misc-fixed идёт первым не по красоте, а по полноте: это базовый Unicode-набор X (пакет
// xfonts-base), и кириллица в нём есть всегда. Крупные helvetica/courier из 100dpi-наборов
// формально тоже iso10646-1, но содержат только латиницу — на живом Xvfb заголовок из них
// выходил рядом пустых квадратов.
var BigCandidates = []Candidate{
	{"-misc-fixed-bold-r-normal--20-*-*-*-*-*-iso10646-1", 20},
	{"-misc-fixed-medium-r-normal--20-*-*-*-*-*-iso10646-1", 20},
	{"-adobe-helvetica-bold-r-normal--34-*-*-*-*-*-iso10646-1", 34},
	{"-*-*-bold-r-normal--24-*-*-*-*-*-iso10646-1", 24},
}

// TextCandidates — кандидаты под основной текст.
var TextCandidates = []Candidate{
	{"-misc-fixed-medium-r-normal--14-*-*-*-*-*-iso10646-1", 14},
	{"-misc-fixed-medium-r-normal--13-*-*-*-*-*-iso10646-1", 13},
	{"-adobe-helvetica-medium-r-normal--14-*-*-*-*-*-iso10646-1", 14},
	{"-*-*-medium-r-normal--14-*-*-*-*-*-iso10646-1", 14},
}

// probeRunes — буквы, которые обязаны быть у шрифта: заглавная и строчная кириллица плюс
// латиница. Проверяем по три, а не по одной: часть наборов несёт только заглавные.
var probeRunes = []rune{'У', 'с', 'т', 'A'}

// PickFonts подбирает пару шрифтов и решает, доступен ли двухбайтовый вывод вообще.
func PickFonts(conn *xgb.Conn, log *slog.Logger) Fonts {
	var f Fonts
	f.Big, f.BigName = OpenFont(conn, BigCandidates)
	f.Text, f.TextName = OpenFont(conn, TextCandidates)
	if log != nil {
		log.Info("x11: шрифты окна", slog.String("заголовок", f.BigName), slog.String("текст", f.TextName))
	}
	f.TwoByte = f.Text != 0
	if !f.TwoByte {
		// Ни один Unicode-шрифт не подошёл: рисуем латиницей серверным "fixed", который
		// есть на любом X-сервере.
		f.Text = OpenFallbackFont(conn, log)
		f.Big = f.Text
		if log != nil {
			log.Warn("x11: Unicode-шрифты недоступны, текст будет на латинице")
		}
	}
	return f
}

// OpenFont возвращает первый кандидат, который ОТКРЫЛСЯ и реально что-то рисует.
func OpenFont(conn *xgb.Conn, candidates []Candidate) (xproto.Font, string) {
	for _, c := range candidates {
		reply, err := xproto.ListFonts(conn, 16, uint16(len(c.Pattern)), c.Pattern).Reply()
		if err != nil {
			continue
		}
		for _, name := range reply.Names {
			f, err := xproto.NewFontId(conn)
			if err != nil {
				return 0, ""
			}
			if err := xproto.OpenFontChecked(conn, f, uint16(len(name.Name)), name.Name).Check(); err != nil {
				continue
			}
			if DrawsCyrillic(conn, f) {
				return f, name.Name
			}
			xproto.CloseFont(conn, f)
		}
	}
	return 0, ""
}

// DrawsCyrillic — есть ли у шрифта НАСТОЯЩИЕ глифы кириллицы.
//
// Ширины здесь недостаточно в обе стороны: у шрифта без нужного глифа сервер подставляет
// символ по умолчанию (ширина ненулевая, на экране пустой квадрат), а у моноширинного
// набора ширина вообще одинакова у всех символов, включая отсутствующие. Поэтому
// спрашиваем таблицу метрик: глиф существует, когда его Charinfo непустой.
func DrawsCyrillic(conn *xgb.Conn, font xproto.Font) bool {
	qf, err := xproto.QueryFont(conn, xproto.Fontable(font)).Reply()
	if err != nil {
		return false
	}
	for _, r := range probeRunes {
		if !GlyphExists(qf, r) {
			return false
		}
	}
	return true
}

// GlyphExists — есть ли у шрифта глиф для кодовой точки (шрифт двухбайтовый, индексация
// как в X11: (byte1-min)*ширина_строки + (byte2-min)).
func GlyphExists(qf *xproto.QueryFontReply, r rune) bool {
	if r > 0xffff {
		return false
	}
	b1, b2 := byte(r>>8), byte(r)
	if b1 < qf.MinByte1 || b1 > qf.MaxByte1 {
		return false
	}
	if uint16(b2) < qf.MinCharOrByte2 || uint16(b2) > qf.MaxCharOrByte2 {
		return false
	}
	if qf.AllCharsExist || len(qf.CharInfos) == 0 {
		return qf.AllCharsExist
	}
	rowLen := int(qf.MaxCharOrByte2-qf.MinCharOrByte2) + 1
	idx := (int(b1)-int(qf.MinByte1))*rowLen + (int(b2) - int(qf.MinCharOrByte2))
	if idx < 0 || idx >= len(qf.CharInfos) {
		return false
	}
	ci := qf.CharInfos[idx]
	// Пустой Charinfo = глифа нет (X11 protocol, §Fonts): у существующего символа хоть
	// одна метрика ненулевая.
	return ci.CharacterWidth != 0 || ci.Ascent != 0 || ci.Descent != 0 ||
		ci.LeftSideBearing != 0 || ci.RightSideBearing != 0
}

// OpenFallbackFont открывает серверный "fixed" (однобайтовый, есть везде).
func OpenFallbackFont(conn *xgb.Conn, log *slog.Logger) xproto.Font {
	f, err := xproto.NewFontId(conn)
	if err != nil {
		return 0
	}
	if err := xproto.OpenFontChecked(conn, f, uint16(len("fixed")), "fixed").Check(); err != nil {
		if log != nil {
			log.Warn("x11: не открылся даже шрифт fixed", slog.Any("error", err))
		}
		return 0
	}
	return f
}

// TextWidth — ширина строки в пикселях по метрикам сервера; 0 означает «шрифт эту строку
// не рисует». Считать ширину самостоятельно нельзя: шрифт подобран по шаблону и его
// метрики заранее неизвестны.
func TextWidth(conn *xgb.Conn, font xproto.Font, s string) int32 {
	if font == 0 {
		return 0
	}
	chars := ToChar2b(s)
	ext, err := xproto.QueryTextExtents(conn, xproto.Fontable(font), chars, uint16(len(chars))).Reply()
	if err != nil {
		return 0
	}
	return ext.OverallWidth
}

// ToChar2b переводит строку в двухбайтовые символы X11 (кодировка iso10646-1 = UCS-2).
// Всё вне BMP заменяется на «?»: суррогатных пар в этом протоколе нет.
func ToChar2b(s string) []xproto.Char2b {
	out := make([]xproto.Char2b, 0, len(s))
	for _, r := range s {
		if r > 0xffff {
			r = '?'
		}
		out = append(out, xproto.Char2b{Byte1: byte(r >> 8), Byte2: byte(r)})
	}
	return out
}

// DrawText рисует строку в точке (x, y).
//
// ImageText8/16 передают длину ОДНИМ байтом, поэтому строки режутся по 255 символов.
// Тексты окон короче, но причина сеанса и повод приезжают с сервера и бывают любыми.
func DrawText(conn *xgb.Conn, d xproto.Drawable, gc xproto.Gcontext, twoByte bool, s string, x, y int16) {
	if s == "" || gc == 0 {
		return
	}
	if twoByte {
		chars := ToChar2b(s)
		if len(chars) > 255 {
			chars = chars[:255]
		}
		xproto.ImageText16(conn, byte(len(chars)), d, gc, x, y, chars)
		return
	}
	b := []byte(s)
	if len(b) > 255 {
		b = b[:255]
	}
	xproto.ImageText8(conn, byte(len(b)), d, gc, x, y, string(b))
}

// DrawCentered рисует строку по центру полосы шириной width.
func DrawCentered(conn *xgb.Conn, d xproto.Drawable, gc xproto.Gcontext, font xproto.Font,
	twoByte bool, s string, y int16, width uint16) {
	if s == "" || gc == 0 {
		return
	}
	x := int16(width) / 4 // запасное положение, если метрики недоступны
	if w := TextWidth(conn, font, s); w > 0 {
		x = (int16(width) - int16(w)) / 2
	}
	DrawText(conn, d, gc, twoByte, s, x, y)
}
