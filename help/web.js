let currentSessionId = null;

function goToMain() {
    window.location.href = '/';
}

function showModal() {
    document.getElementById('infoModal').style.display = 'flex';
}

function hideModal() {
    document.getElementById('infoModal').style.display = 'none';
}

function showNotification(message, type = 'info', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('show');
    }, 100);

    setTimeout(() => {
        notification.classList.remove('show');
        notification.classList.add('hide');
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 500);
    }, duration);
}

function addMessageToTerminal(prompt, text, className = 'system') {
    const terminalBody = document.getElementById('terminalBody');
    const message = document.createElement('div');
    message.className = `message ${className}`;
    message.innerHTML = `<span class="prompt">${prompt}</span> ${text}`;
    terminalBody.appendChild(message);
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

function checkForResponse() {
    if (!currentSessionId) return;

    fetch(`/check_response/${currentSessionId}`)
        .then(response => response.json())
        .then(data => {
            if (data.responded && data.admin_response) {
                addMessageToTerminal('IT hub:', data.admin_response, 'admin');
                showNotification('Получен ответ от администратора', 'success');
            } else if (data.ignored) {
                addMessageToTerminal('IT hub:', data.admin_response, 'admin');
                showNotification('Обращение принято', 'info');
                currentSessionId = null;
            } else if (data.dialog_ended) {
                addMessageToTerminal('IT hub:', data.admin_response, 'admin');
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

    if (!message) return;

    addMessageToTerminal('Student:', message, 'user');
    input.value = '';

    document.getElementById('sendButton').disabled = true;
    document.getElementById('sendButton').textContent = 'Отправка...';

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
        .then(response => response.json())
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
            showNotification('Ошибка соединения', 'error');
        })
        .finally(() => {
            document.getElementById('sendButton').disabled = false;
            document.getElementById('sendButton').textContent = 'Отправить';
        });
}

document.addEventListener('DOMContentLoaded', function () {
    const input = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');

    input.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
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
});