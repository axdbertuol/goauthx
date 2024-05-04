package repository

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

type Getter interface {
	GetAll(entities interface{}, req *http.Request) error
	GetByName(entities interface{}, name string, req *http.Request) error
	GetById(entity interface{}, id interface{}) error
}

type Paginator interface {
	ApplyPagination(req *http.Request) *gorm.DB
}

type Transactional interface {
	Create(entity interface{}) error
	Update(entity interface{}) error
	Delete(entity interface{}, id interface{}) error
	Save(entity interface{}) error
}
type StorableRepository interface {
	Getter
	Transactional
	Paginator
}
type GormRepository struct {
	Db *gorm.DB
	StorableRepository
}

func ApplyPagination(req *http.Request, db *gorm.DB) *gorm.DB {
	if req.URL.RawQuery != "" {
		return db.Scopes(Paginate(req))
	}
	return db
}

func (gr *GormRepository) GetDb() *gorm.DB {
	return gr.Db
}

func (gr *GormRepository) ApplyPagination(req *http.Request) *gorm.DB {
	if req.URL.RawQuery != "" {
		return gr.Db.Scopes(Paginate(req))
	}
	return gr.Db
}

func Paginate(r *http.Request) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		q := r.URL.Query()
		page, _ := strconv.Atoi(q.Get("page"))
		if page <= 0 {
			page = 1
		}

		pageSize, _ := strconv.Atoi(q.Get("page_size"))
		switch {
		case pageSize > 100:
			pageSize = 100
		case pageSize <= 0:
			pageSize = 10
		}

		offset := (page - 1) * pageSize
		return db.Offset(offset).Limit(pageSize)
	}
}

func (r *GormRepository) GetAll(entities interface{}, req *http.Request) error {
	err := r.Db.Scopes(Paginate(req)).Find(entities).Error
	if err != nil {
		return fmt.Errorf("failed to get all entities: %w", err)
	}
	return nil
}

func (r *GormRepository) GetByName(entities interface{}, name string, req *http.Request) error {

	name = strings.ToLower(name)
	if err := r.Db.
		Scopes(Paginate(req)).
		Where("lower(name) LIKE ?", "%"+name+"%").
		Find(entities).Error; err != nil {
		return fmt.Errorf("failed to get entities by name: %w", err)
	}
	return nil
}

func (r *GormRepository) GetById(entity interface{}, id interface{}) error {
	if err := r.Db.
		First(entity, id).Error; err != nil {
		return fmt.Errorf("failed to get entity by ID: %w", err)
	}
	return nil
}

func (r *GormRepository) Create(entity interface{}) error {
	if err := r.Db.
		Create(entity).Error; err != nil {
		return err
	}
	return nil
}

func (r *GormRepository) Update(entity interface{}) error {

	if err := r.Db.
		Model(entity).
		Updates(entity).Error; err != nil {
		return fmt.Errorf("failed to update entity: %w", err)
	}
	return nil
}

func (r *GormRepository) Delete(entity interface{}, id interface{}) error {
	if err := r.Db.Delete(entity, id).Error; err != nil {
		return fmt.Errorf("failed to delete entity: %w", err)
	}
	return nil
}

func (r *GormRepository) Save(entity interface{}) error {
	if err := r.Db.Save(entity).Error; err != nil {
		return fmt.Errorf("failed to save entity: %w", err)
	}
	return nil
}
