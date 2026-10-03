package app.sprout.identity.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.SocketException;
import java.sql.SQLException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.TransactionSystemException;

/** Recognising a lost database connection however deep it's wrapped. */
class DatabaseUnreachableTest {

    @Test
    void aFailedRollbackAfterALostConnectionCountsAsDatabaseDown() {
        TransactionSystemException rollbackFailed = new TransactionSystemException("JDBC rollback failed",
                new SQLException("An I/O error occurred while sending to the backend.", "08006", new SocketException("Broken pipe")));
        assertThat(ProblemHandler.databaseUnreachable(rollbackFailed)).isTrue();
    }

    @Test
    void connectionClassSqlStatesCount() {
        assertThat(ProblemHandler.databaseUnreachable(new RuntimeException(new SQLException("refused", "08001")))).isTrue();
    }

    @Test
    void ordinaryDataErrorsDoNot() {
        assertThat(ProblemHandler.databaseUnreachable(new DataIntegrityViolationException("duplicate key",
                new SQLException("duplicate key", "23505")))).isFalse();
        assertThat(ProblemHandler.databaseUnreachable(new IllegalStateException("bug"))).isFalse();
    }
}
