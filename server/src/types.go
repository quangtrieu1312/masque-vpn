package main

import (
  "gorm.io/gorm"
)

type Client struct {
    gorm.Model
    UUID string `gorm:"primaryKey"`
    Name string
    LastSeen uint64
    Roles []*Role `gorm:"many2many:clients_roles"`
    Resources []*Resource `gorm:"many2many:clients_resources"`
}

type IP struct {
    gorm.Model
    ClientID uint
    Client Client
    Value string
}

type Role struct {
    gorm.Model
    Clients []*Client `gorm:"many2many:clients_roles"`
    Resources []*Resource `gorm:"many2many:roles_resources"`
}

type Resource struct {
    gorm.Model
    Clients []*Client `gorm:"many2many:clients_resources"`
    Roles []*Role `gorm:"many2many:roles_resources"`
}

