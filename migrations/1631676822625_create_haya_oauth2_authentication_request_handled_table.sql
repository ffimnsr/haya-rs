-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_oauth2_authentication_request_handled
(
    challenge VARCHAR(40) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    remember boolean NOT NULL,
    remember_for INTEGER NOT NULL,
    error TEXT NOT NULL,
    acr TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    authenticated_at TIMESTAMPTZ,
    was_used boolean NOT NULL,
    forced_subject_identifier VARCHAR(255) DEFAULT '',
    context TEXT NOT NULL DEFAULT '{}',
    CONSTRAINT hydra_oauth2_authentication_request_handled_pkey PRIMARY KEY (challenge),
    CONSTRAINT hydra_oauth2_authentication_request_handled_challenge_fk FOREIGN KEY (challenge)
        REFERENCES public.hydra_oauth2_authentication_request (challenge) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

-- !DOWN
