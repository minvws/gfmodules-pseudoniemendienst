#!/usr/bin/env bash

GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
NC="\033[0m"
RED="\033[31m"

SCRIPT=$(readlink -f $0)
BASEDIR=$(dirname $SCRIPT)/..
SQLDIR="$BASEDIR/sql"

# Check for required environment variable DSN
if [ -z "$DSN" ]; then
    echo -e "${RED}❌ Error: The DSN environment variable is not set. Please set $DSN to run migrations.${NC}"
    exit 1
fi

if [ ! -d "$SQLDIR" ]; then
    echo -e "${RED}❌ Error: 'sql' directory not found. No migrations can be processed.${NC}"
    exit 1
fi

# Setup temporary file and begin transaction
TEMP_FILE=$(mktemp /tmp/migration_combined.XXXXXX.sql)
# Set a trap to ensure the temporary file is cleaned up even if the script fails
trap "rm -f $TEMP_FILE" EXIT

cat << EOF >> "$TEMP_FILE"
BEGIN;
SET timezone = 'UTC';
EOF


# Check Migration Table Existence by running the command and capturing output
MIGRATION_TABLE_EXISTS=$(psql $DSN -tA <<EOF
SELECT EXISTS(SELECT 1
    FROM pg_tables
    WHERE schemaname = 'public'
        AND tablename = 'migrations'
);
EOF
)

if [ "$MIGRATION_TABLE_EXISTS" = "f" ]; then
  echo -e "${YELLOW}⚠️ Migration table does not exist. Creating migrations table.${NC}"

  # create the migration table
  cat << EOF >> "$TEMP_FILE"
CREATE TABLE migrations (
    id serial PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    name VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL
  );
EOF
fi

pending_migrations=()

for file in $SQLDIR/*.sql; do
  basename="$(basename $file)"
  if [ "$MIGRATION_TABLE_EXISTS" = "f" ]; then
    echo -e "${YELLOW}▶️ Found pending migration: $basename ${NC}"
    pending_migrations+=("$file")
  else
    FILE_CHECKSUM=$(sha256sum "$file" | awk '{print $1}')
    APPLIED_CHECKSUM=$(psql $DSN -tA -c "SELECT checksum FROM migrations WHERE name = '$basename';" | head -n 1)

    if [ -z $APPLIED_CHECKSUM ]; then
      echo -e "${YELLOW}▶️ Found pending migration: $basename${NC}"
      pending_migrations+=("$file")
    else
      # check if file checksum is not equal to applied checksum:
      if [ "$FILE_CHECKSUM" != "$APPLIED_CHECKSUM" ]; then
        echo -e "${RED}🚨 CRITICAL: Checksum mismatch detected for $basename. Migration process aborted to prevent data corruption.${NC}"
        exit 1;
      else
        echo -e "${GREEN}▶️ Already applied migration: $basename${NC}"
      fi
    fi
  fi
done

for file in "${pending_migrations[@]}"; do
  echo "--------------------------------------------------------------------------" >> "$TEMP_FILE"
  echo "-- Migration file: $(basename "$file")" >> "$TEMP_FILE"
  cat "$file" >> "$TEMP_FILE"
  CHECKSUM=$(sha256sum "$file" | awk '{print $1}')
  echo "-- Update migrations: " >> "$TEMP_FILE"
  echo "INSERT INTO migrations (name, checksum) VALUES ('$(basename "$file")', '${CHECKSUM}');" >> "$TEMP_FILE"
done

echo "COMMIT;" >> $TEMP_FILE

if psql -v ON_ERROR_STOP=1 $DSN -f "$TEMP_FILE" -q -o /dev/null; then
  echo -e "${GREEN}✅ Successfully applied all migrations and recorded them.${NC}"
else
  echo -e "${RED}❌ Failed to apply migrations. Transaction rolled back. No permanent changes were made.${NC}"
  exit 1
fi

echo -e "${BLUE}✅ Migration process finished.${NC}"
