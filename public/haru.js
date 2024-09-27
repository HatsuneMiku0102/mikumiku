document.addEventListener('DOMContentLoaded', function () {
    const chatBox = document.getElementById('chat-box');
    const chatTrigger = document.getElementById('haru-chat-trigger');
    const closeChatButton = document.getElementById('close-chat');
    const personalityCircle = document.getElementById('personalityCircle');
    const sendMessageButton = document.getElementById('send-message');
    const chatInput = document.getElementById('chat-input');
    const chatContent = document.getElementById('chat-content');

    // Open the chat box
    const openChat = () => {
        chatBox.style.display = 'flex'; // Show chat box
    };

    // Close the chat box
    const closeChat = () => {
        chatBox.style.display = 'none'; // Hide chat box
    };

    chatTrigger.addEventListener('click', openChat);
    personalityCircle.addEventListener('click', openChat);
    closeChatButton.addEventListener('click', closeChat);

    // Send message when the send button is clicked
    sendMessageButton.addEventListener('click', async function () {
        const userMessage = chatInput.value.trim();
        if (userMessage) {
            addMessageToChat(userMessage, 'user-message');
            chatInput.value = '';
            const botResponse = await getGPTResponse(userMessage);
            addMessageToChat(botResponse, 'bot-message');
        }
    });

    // Function to add a new message to the chat window
    function addMessageToChat(message, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);
        messageElement.textContent = message;
        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight; // Scroll to bottom
    }

    // Fetch response from GPT-4 API using OpenAI API
    async function getGPTResponse(userMessage) {
        try {
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}` // Using Heroku environment variable
                },
                body: JSON.stringify({
                    model: 'gpt-4',
                    messages: [{ role: 'user', content: userMessage }]
                })
            });

            if (!response.ok) {
                throw new Error(`Error: ${response.statusText}`);
            }

            const data = await response.json();
            const botMessage = data.choices[0].message.content;
            return botMessage;
        } catch (error) {
            console.error('Error fetching GPT-4 response:', error);
            return "Sorry, I'm having trouble connecting to the server.";
        }
    }
});
