let currentSessionId = null;

function goToMain() {
    window.location.href = '/';
}

function showModal() {
    document.getElementById('infoModal').style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

function hideModal() {
    document.getElementById('infoModal').style.display = 'none';
    document.body.style.overflow = 'auto';
}

function showNotification(message, type = 'info', duration = 4000) {
    const notification = document.createElement('div');
    notification.className = `mobile-notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('show');
    }, 100);

    setTimeout(() => {
        notification.classList.remove('show');
        notification.classList.add('hide');
        setTimeout(() => {
            if (notification.parentNode) {
                document.body.removeChild(notification);
            }
        }, 500);
    }, duration);
}

function addMessageToTerminal(prompt, text, className = 'mobile-system') {
    const terminalBody = document.getElementById('terminalBody');
    const message = document.createElement('div');
    message.className = `mobile-message ${className}`;
    message.innerHTML = `<span class="mobile-prompt">${prompt}</span> ${text}`;
    terminalBody.appendChild(message);
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

function checkForResponse() {
    if (!currentSessionId || !/^[a-f0-9]{32}$/.test(currentSessionId)) return;

    fetch(`/check_response/${currentSessionId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.responded && data.admin_response) {
                addMessageToTerminal('IT hub:', data.admin_response, 'mobile-admin');
                showNotification('Получен ответ от администратора', 'success');
            } else if (data.ignored) {
                addMessageToTerminal('IT hub:', data.admin_response, 'mobile-admin');
                showNotification('Обращение принято', 'info');
                currentSessionId = null;
            } else if (data.dialog_ended) {
                addMessageToTerminal('IT hub:', data.admin_response, 'mobile-admin');
                showNotification('Диалог завершен администратором', 'info');
                currentSessionId = null;
            } else if (currentSessionId) {
                setTimeout(checkForResponse, 3000);
            }
        })
        .catch(error => {
            console.error('Error checking response:', error);
            if (currentSessionId) {
                setTimeout(checkForResponse, 5000);
            }
        });
}

function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();

    if (!message) {
        showNotification('Пожалуйста, введите сообщение', 'error');
        return;
    }

    if (message.length > 1000) {
        showNotification('Сообщение слишком длинное (макс. 1000 символов)', 'error');
        return;
    }

    addMessageToTerminal('Student:', message, 'mobile-user');
    input.value = '';

    const sendButton = document.getElementById('sendButton');
    sendButton.disabled = true;
    sendButton.textContent = '...';

    fetch('/send_help_message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            message: message,
            user_agent: navigator.userAgent,
        })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                showNotification('Сообщение отправлено администрации', 'success');
                currentSessionId = data.session_id;
                setTimeout(checkForResponse, 3000);
            } else {
                showNotification(`Ошибка отправки: ${data.error || 'Попробуйте позже'}`, 'error');
            }
        })
        .catch(error => {
            console.error('Error sending message:', error);
            showNotification('Ошибка соединения', 'error');
        })
        .finally(() => {
            sendButton.disabled = false;
            sendButton.textContent = 'Отпр';
        });
}

document.addEventListener('DOMContentLoaded', function () {
    const input = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');

    input.addEventListener('input', function () {
        if (this.value.length > 1000) {
            this.value = this.value.substring(0, 1000);
            showNotification('Максимальная длина сообщения: 1000 символов', 'error');
        }
    });

    input.addEventListener('keypress', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            hideModal();
        }
    });

    document.getElementById('infoModal').addEventListener('click', function (event) {
        if (event.target === this) {
            hideModal();
        }
    });

    document.addEventListener('touchstart', function () { }, { passive: true });
});