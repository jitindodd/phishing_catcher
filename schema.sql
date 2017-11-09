DROP SCHEMA IF EXISTS website CASCADE;
CREATE SCHEMA website;

CREATE TABLE website.phishy_site (
    url text PRIMARY KEY,
    score integer NOT NULL,
    category text NOT NULL
);

INSERT INTO website.phishy_site (url, score, category) values ('test.com', 52, 'Potential');
INSERT INTO website.phishy_site (url, score, category) values ('bad.com', 99, 'Suspicious');
