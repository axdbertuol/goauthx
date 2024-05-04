variable "cloud_token" {
  type    = string
  default = getenv("ATLAS_TOKEN")
}

atlas {
  cloud {
    token = var.cloud_token
  }
}

data "remote_dir" "migrations" {
  name = "kommshop-products"
}


data "external_schema" "gorm" {
  program = [
    "go",
    "run",
    // "-mod=mod",
    "ariga.io/atlas-provider-gorm",
    "load",
    "--path", "./internal/models",
    "--dialect", "postgres", // | postgres | sqlite
  ]
}

env "cloud" {
  url = getenv("DATABASE_URL_DEV")

  migration {
    dir = data.remote_dir.migrations.url
  }
}

env "gorm" {
  src = data.external_schema.gorm.url
  dev = "docker://postgres/15/test?search_path=public"
  url = getenv("DATABASE_URL_DEV")

  migration {
    dir = "file://db/migrations"
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

lint {
  data_depend {
    error = true
  }
}