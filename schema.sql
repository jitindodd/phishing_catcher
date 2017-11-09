DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;

DROP SCHEMA IF EXISTS website CASCADE;
CREATE SCHEMA website;

CREATE TABLE website.phishy_sites (
  url integer PRIMARY KEY,
  score integer NOT NULL,
  category text NOT NULL,
);
