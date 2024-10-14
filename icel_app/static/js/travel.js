function showForm() {
  document.getElementById('travelFormContainer').style.left = '0px';
  document.querySelector('.travelForm').style.visibility = 'hidden';
}

function showCarForm() {
  document.getElementById('travelCarFormContainer').style.right = '0px';
  document.querySelector('.travelForm').style.visibility = 'hidden';
}

function hideForm() {
  document.getElementById('travelFormContainer').style.left = '-800px';
  document.getElementById('travelCarFormContainer').style.right = '-800px';
  document.querySelector('.travelForm').style.visibility = 'visible';
}

