package com.myapp.auth.application;

/**
 * Fehler beim Aufruf von Keycloak.
 *
 * Wichtig ist die Unterscheidung zwischen "Keycloak hat geantwortet und
 * abgelehnt" (status &gt; 0) und "Keycloak war gar nicht erreichbar"
 * (status == 0). Nur im ersten Fall darf der Client seine Session verwerfen.
 */
public class KeycloakException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** HTTP-Status von Keycloak, 0 wenn es keine Antwort gab (Timeout, Connection refused, ...). */
    private final int status;

    /** OAuth-Fehlercode aus dem Body ("invalid_grant", "invalid_scope", ...), kann null sein. */
    private final String error;

    public KeycloakException(int status, String error, String description, Throwable cause) {
        super(description, cause);
        this.status = status;
        this.error = error;
    }

    public int getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }

    /** Keine HTTP-Antwort erhalten. */
    public boolean isTransportFailure() {
        return status == 0;
    }

    /**
     * Keycloak hat Zugangsdaten bzw. Refresh Token geprueft und abgelehnt.
     * Alles andere (invalid_client, 5xx, Timeout) ist ein Problem auf unserer
     * Seite und sagt nichts ueber den Nutzer aus.
     */
    public boolean isGrantRejected() {
        return (status == 400 || status == 401) && "invalid_grant".equals(error);
    }

    /** Der angefragte Scope ist fuer Client oder Nutzer nicht erlaubt. */
    public boolean isScopeRejected() {
        return status == 400 && ("invalid_scope".equals(error) || "not_allowed".equals(error));
    }
}
