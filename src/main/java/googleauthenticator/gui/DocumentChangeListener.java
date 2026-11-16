package googleauthenticator.gui;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** Adapts Swing's document events to one callback for any content change. */
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
final class DocumentChangeListener implements DocumentListener {
    private final Runnable onChange;

    @Override
    public void insertUpdate(DocumentEvent event) {
        onChange.run();
    }

    @Override
    public void removeUpdate(DocumentEvent event) {
        onChange.run();
    }

    @Override
    public void changedUpdate(DocumentEvent event) {
        onChange.run();
    }
}
