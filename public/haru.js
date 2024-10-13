// public/js/chat.js

document.addEventListener('DOMContentLoaded', () => {
    const chatBox = document.getElementById('chat-box');
    const chatContent = document.getElementById('chat-content');
    const chatInput = document.getElementById('chat-input');
    const sendMessageButton = document.getElementById('send-message');
    const closeChatButton = document.getElementById('close-chat');
    const openChatButton = document.getElementById('open-chat');

    // Generate or retrieve a sessionId
    let sessionId = localStorage.getItem('sessionId');
    if (!sessionId) {
        sessionId = generateUUID();
        localStorage.setItem('sessionId', sessionId);
    }

    // Function to generate a simple UUID
    function generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0,
                  v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

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
        messageElement.innerHTML = `
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
                body: JSON.stringify({ message, sessionId }),
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
