-- Fictional customers the public sandbox lets visitors explore as. They sign in like anyone, but can't
-- turn on two-factor and never lock after wrong passwords, so one visitor can't spoil one for the next.
ALTER TABLE users ADD COLUMN demo boolean NOT NULL DEFAULT false;
