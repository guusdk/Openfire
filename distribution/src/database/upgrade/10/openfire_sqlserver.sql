
CREATE TABLE jiveSASLAuthorized (
  username        NVARCHAR(64)     NOT NULL,
  principal       NVARCHAR(1500)   NOT NULL,
  CONSTRAINT jiveSASLAuthoirzed_pk PRIMARY KEY (username, principal)
);

UPDATE jiveVersion set version=10 where name = 'openfire';
