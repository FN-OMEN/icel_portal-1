document.getElementById('contactForm').addEventListener('submit', function(event) {
  event.preventDefault();
  let error = '';
  
  const firstName = document.getElementById('firstName').value;
  const lastName = document.getElementById('lastName').value;
  const email = document.getElementById('email').value;
  
  if (!firstName || !lastName || !email) {
      error = 'Please fill in all required fields.';
  }
  
  if (error) {
      document.getElementById('error').textContent = error;
  } else {
      document.getElementById('error').textContent = ' ';
      alert('Form submitted successfully!');
      // Optionally, add code here to send the form data to a server
      document.getElementById('contactForm').reset();
  }
});

