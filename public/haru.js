// public/js/chat.js

document.addEventListener('DOMContentLoaded', () => {
    const chatBox = document.getElementById('chat-box');
    const chatContent = document.getElementById('chat-content');
    const chatInput = document.getElementById('chat-input');
    const sendMessageButton = document.getElementById('send-message');
    const closeChatButton = document.getElementById('close-chat');
    const openChatButton = document.getElementById('open-chat');

    // Open Chat Function
    function openChat() {
        chatBox.classList.add('open');
        chatBox.classList.remove('closed');
        chatInput.focus();
    }

    // Close Chat Function
    function closeChat() {
        chatBox.classList.remove('open');
        chatBox.classList.add('closed');
    }

    // Append Message to Chat
    function appendMessage(content, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);
        const icon = className === 'bot-message' ? '<i class="fas fa-robot"></i>' : '<i class="fas fa-user"></i>';
        messageElement.innerHTML = `
            ${icon}
            <div class="message-content">${content}</div>
        `;
        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight;
    }

    // Send Message to Server
    async function sendMessage() {
        const message = chatInput.value.trim();
        if (message === '') return;

        appendMessage(message, 'user-message');
        chatInput.value = '';
        chatInput.disabled = true;
        sendMessageButton.disabled = true;

        try {
            const response = await fetch('/api/openai-chat', { // Ensure this matches your server endpoint
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message }),
            });

            if (!response.ok) {
                appendMessage('Sorry, something went wrong. Please try again.', 'bot-message');
                return;
            }

            const data = await response.json();
            const botResponse = data.response || 'Sorry, I couldn’t process that.';

            appendMessage(botResponse, 'bot-message');
        } catch (error) {
            console.error('Error:', error);
            appendMessage('Sorry, something went wrong. Please try again.', 'bot-message');
        } finally {
            chatInput.disabled = false;
            sendMessageButton.disabled = false;
            chatInput.focus();
        }
    }

    // Event Listeners
    sendMessageButton.addEventListener('click', sendMessage);

    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    closeChatButton.addEventListener('click', closeChat);
    openChatButton.addEventListener('click', openChat);

    // Accessibility: Close chat with Escape key when focused inside the chat
    chatBox.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeChat();
            openChatButton.focus();
        }
    });

    // Initialize chat as closed
    closeChat();
});
