SQLite
CREATE TABLE faculty_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    school_id text NOT NULL,
    firstname TEXT NOT NULL,
    lastname TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    avatar TEXT,
    datecreated DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO faculty_list(school_id,firstname,lastname,email,password)
VALUES ('100073','Beia', 'Banca','beiabanca@email.com','pretty');

SELECT * FROM users;
CREATE TABLE subject_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL,
    subject TEXT NOT NULL,
    description TEXT NOT NULL UNIQUE
);

INSERT INTO subject_list(code,subject,description)
 VALUES ('CC106', 'Applications Development and Emerging Technologies','flask learning');


CREATE TABLE evaluation_list (
    evaluation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    academic_id INTEGER NOT NULL,
    class_id INTEGER NOT NULL,
    student_id INTEGER NOT NULL,
    subject_id INTEGER NOT NULL,
    faculty_id INTEGER NOT NULL,
    restriction_id INTEGER NOT NULL,
    date_taken DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO evaluation_list(academic_id, class_id, student_id, subject_id, faculty_id, restriction_id)
VALUES ('2','1','2', '1', '2', '1');

CREATE TABLE evaluation_answers (
    evaluation_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    rate INTEGER NOT NULL
);
INSERT INTO evaluation_answers(evaluation_id,question_id, rate)
VALUES ('2','1','2');

CREATE TABLE criteria_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT ,
    criteria text NOT NULL,
    order_by INTEGER NOT NULL
);
INSERT INTO criteria_list(criteria, order_by)
VALUES ('CC106','2');

CREATE TABLE class_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT ,
    curriculum text NOT NULL,
    level text NOT NULL,
    section TEXT NOT NULL
);
INSERT INTO class_list(curriculum, level, section)
VALUES ('BSIT','3', 'A');

CREATE TABLE academic_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT ,
    year text NOT NULL,
    semester INTEGER NOT NULL,
    is_default INTEGER NOT NULL,
    status INTEGER NOT NULL
);
INSERT INTO academic_list(year, semester, is_default, status)
VALUES ('2020-2024','2', '1', '0');


DROP TABLE IF EXISTS evaluation_answers;
