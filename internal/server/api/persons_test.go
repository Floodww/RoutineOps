package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

type personResp struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Source      string `json:"source"`
}

func createPerson(t *testing.T, rtr http.Handler, tok, name, email string) personResp {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"display_name": name, "email": email})
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/persons", body, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create person: got %d %s, want 201", w.Code, w.Body)
	}
	var p personResp
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}

// Путь оператора целиком, ради которого всё и делалось: завести владельца (ФИО + почта,
// без приглашения и без аккаунта) и назначить его на устройство.
func TestPerson_CreateAndAssignAsOwner(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "owner-flow", "windows")

	p := createPerson(t, rtr, tok, "Иван Иванов", "ivanov@example.com")
	if p.Source != "manual" {
		t.Errorf("source = %q, want manual", p.Source)
	}

	body, _ := json.Marshal(map[string]string{"person_id": p.ID})
	if w := authedDo(t, rtr, http.MethodPut, "/api/v1/devices/"+deviceID+"/owner", body, tok); w.Code != http.StatusNoContent {
		t.Fatalf("assign owner: got %d %s, want 204", w.Code, w.Body)
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices/"+deviceID, nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("get device: %d", w.Code)
	}
	var got struct {
		Device struct {
			OwnerPersonID    string `json:"owner_person_id"`
			OwnerPersonName  string `json:"owner_person_name"`
			OwnerPersonEmail string `json:"owner_person_email"`
		} `json:"device"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode device: %v", err)
	}
	dev := got.Device
	if dev.OwnerPersonID != p.ID || dev.OwnerPersonName != "Иван Иванов" || dev.OwnerPersonEmail != "ivanov@example.com" {
		t.Fatalf("владелец в карточке: %+v", dev)
	}

	// Снятие.
	body, _ = json.Marshal(map[string]string{"person_id": ""})
	if w := authedDo(t, rtr, http.MethodPut, "/api/v1/devices/"+deviceID+"/owner", body, tok); w.Code != http.StatusNoContent {
		t.Fatalf("clear owner: got %d %s", w.Code, w.Body)
	}
}

// Ввод оператора валидируется на границе: карточка без имени нечитаема в списке
// владельцев, а мусор в почте молча жил бы в панели.
func TestPerson_ValidatesInput(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	for _, tc := range []struct{ name, body string }{
		{"пустое ФИО", `{"display_name":"","email":"a@b.com"}`},
		{"ФИО из пробелов", `{"display_name":"   "}`},
		{"битая почта", `{"display_name":"Иван","email":"не-почта"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := authedDo(t, rtr, http.MethodPost, "/api/v1/persons", []byte(tc.body), tok); w.Code != http.StatusBadRequest {
				t.Errorf("got %d %s, want 400", w.Code, w.Body)
			}
		})
	}

	// Почта необязательна — не у каждого сотрудника есть корпоративная.
	p := createPerson(t, rtr, tok, "Без Почты", "")
	if p.Email != "" {
		t.Errorf("email = %q, want пусто", p.Email)
	}
}

// Заведение владельцев меняет состояние парка — это работа it_admin, не viewer'а.
func TestPerson_ViewerCannotManage(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	admin := authToken(t, rtr, db)
	viewer := tokenForRole(t, rtr, db, "viewer", "viewer_persons_")
	p := createPerson(t, rtr, admin, "Иван Иванов", "")

	body, _ := json.Marshal(map[string]string{"display_name": "Подмена"})
	if w := authedDo(t, rtr, http.MethodPost, "/api/v1/persons", body, viewer); w.Code != http.StatusForbidden {
		t.Errorf("создание viewer'ом: got %d, want 403", w.Code)
	}
	if w := authedDo(t, rtr, http.MethodPut, "/api/v1/persons/"+p.ID, body, viewer); w.Code != http.StatusForbidden {
		t.Errorf("правка viewer'ом: got %d, want 403", w.Code)
	}
	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/persons/"+p.ID, nil, viewer); w.Code != http.StatusForbidden {
		t.Errorf("удаление viewer'ом: got %d, want 403", w.Code)
	}
}

// Удаление карточки не роняет и не скрывает устройство — оно просто остаётся без
// владельца (owner_directory_id ON DELETE SET NULL).
func TestPerson_DeleteLeavesDeviceWithoutOwner(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "owner-del", "windows")
	p := createPerson(t, rtr, tok, "Уволенный Сотрудник", "")

	body, _ := json.Marshal(map[string]string{"person_id": p.ID})
	if w := authedDo(t, rtr, http.MethodPut, "/api/v1/devices/"+deviceID+"/owner", body, tok); w.Code != http.StatusNoContent {
		t.Fatalf("assign: %d %s", w.Code, w.Body)
	}
	if w := authedDo(t, rtr, http.MethodDelete, "/api/v1/persons/"+p.ID, nil, tok); w.Code != http.StatusNoContent {
		t.Fatalf("delete person: %d %s", w.Code, w.Body)
	}

	w := authedDo(t, rtr, http.MethodGet, "/api/v1/devices/"+deviceID, nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("устройство пропало после удаления владельца: %d", w.Code)
	}
	var got struct {
		Device struct {
			OwnerPersonID string `json:"owner_person_id"`
		} `json:"device"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Device.OwnerPersonID != "" {
		t.Errorf("владелец не снят: %q", got.Device.OwnerPersonID)
	}
}
