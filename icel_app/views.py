from django.conf import settings
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.files.storage import FileSystemStorage
from django.core.mail import send_mail
from django.shortcuts import redirect, render
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.http import HttpResponse
from django.views import View
from django.core.mail import EmailMessage
from .forms import SignUpForm
from django.utils.crypto import get_random_string
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import update_session_auth_hash


# Homepage view
@login_required
def homepage(request):
    return render(request, "homepage.html")



def incident_form(request):
    if request.method == "POST":
        id_no = request.POST.get("id_no")
        date = request.POST.get("date")
        department = request.POST.get("department")
        location = request.POST.get("location")
        description = request.POST.get("description")
        corrective_action = request.POST.get("corrective_action")
        date_observed = request.POST.get("date_observed")
        date_reported = request.POST.get("date_reported")
        observed_by = request.POST.get("observed_by")
        category = request.POST.get("category")
        incident_types = request.POST.getlist("incident_type")
        incident_upload = request.FILES.get("incident_upload")

        # Construct the email
        subject = f"Incident Report from {observed_by}"
        message = f"""
        Incident Report Details

        ID Number: {id_no}
        Date of Incident: {date}
        Department: {department}

        Incident Information:
        - Types of Incident: {', '.join(incident_types)}
        - Location: {location}
        - Description: {description}

        Corrective Action Taken:
        - Action: {corrective_action}

        Timeline:
        - Date Observed: {date_observed}
        - Date Reported: {date_reported}

        Category: {category}

        This report has been submitted by {observed_by}. Please review the details and take the necessary actions.
        """

        # Create an email message object
        email = EmailMessage(
            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=["isaiahdurojaiye9@gmail.com"],
        )

        # Attach the file if uploaded
        if incident_upload:
            email.attach(incident_upload.name, incident_upload.read(), incident_upload.content_type)

        # Send the email
        email.send(fail_silently=False)

        return redirect("success")
    
    return render(request, "incident_form.html")



# POOL_CAR_request_view
def pool_car_request(request):
    if request.method == "POST":
        date_requested = request.POST.get("R-datecheckin")
        requestor_name = request.POST.get("requestor_name")
        phone_number = request.POST.get("phone_number")
        car_no = request.POST.get("car_no")
        pick_up_location = request.POST.get("pick_up_location")
        drop_off_destination = request.POST.get("drop_off_destination")
        return_location = request.POST.get("return_location")
        purpose_of_trip = request.POST.get("purpose_of_trip")
        departure_date = request.POST.get("departure_date")
        return_date = request.POST.get("return_date")
        departure_time = request.POST.get("departure_time")
        estimated_return_time = request.POST.get("estimated_return_time")
        director_name = request.POST.get("director_name")
        director_designation = request.POST.get("director_designation")
        director_email = request.POST.get("director_email")


        subject = f"Pool Car Request - {requestor_name} ({pick_up_location} to {drop_off_destination})"
        message = f"""
Dear Logistics Team,

Please be informed that a pool car request has been submitted by {requestor_name}. Below are the details for your review and processing:

Requestor Information:
- Name: {requestor_name}
- Phone Number: {phone_number}
- Number of Cars Requested: {car_no}

Trip Details:
- Pick-up Location: {pick_up_location}
- Drop-off Destination: {drop_off_destination}
- Return Location: {return_location}
- Purpose of Trip: {purpose_of_trip}

Schedule:
- Date of Request: {date_requested}
- Departure Date: {departure_date}
- Departure Time: {departure_time}
- Estimated Return Date: {return_date}
- Estimated Return Time: {estimated_return_time}

Director/Supervisor Information:
- Name: {director_name}
- Designation: {director_designation}
- Contact Email: {director_email}

Please ensure that the necessary arrangements are made accordingly. Should you need further information, do not hesitate to reach out to the requestor.

Best regards,
{requestor_name}
"""
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                ["isaiahdurojaiye9@gmail.com", "ayokanmiamos@gmail.com"],
                fail_silently=False,
            )
            return redirect("success")
        except Exception as e:
            print(f"Error sending email: {e}")
            return render(
                request, "pool_car_request.html", {"error": "Failed to send the email."}
            )

    return render(request, "pool_car_request.html")


def contact_view(request):
    if request.method == "POST":
        first_name = request.POST.get("firstName")
        last_name = request.POST.get("lastName")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        message = request.POST.get("message")

        # Construct the email subject and body
        subject = f"IT Complaint Form Submitted by {first_name} {last_name}"

        body = f"""
        Dear IT Support Team,

        You have received a new complaint form. Below are the details:

        Complaint Details:
        Full Name: {first_name} {last_name}
        Email Address: {email}
        Phone Number: {phone}


        Complaint Message:
        {message}

        Please address this complaint as soon as possible.

        Best regards,
        {first_name} {last_name}
        """


        # Send the email
        try:
            send_mail(
                subject,
                body,
                'ondavid59@gmail.com',  # FROM email
                ['isaiahdurojaiye9@gmail.com'],  # Recipient email
                fail_silently=False  # Set to False to catch errors
            )
            # Success message
            messages.success(request, 'Your message has been sent successfully!')
            # Redirect to success page
            return redirect('success')
        except Exception as e:
            messages.error(request, 'There was an error sending your message. Please try again.')
            print(f"Error sending email: {e}")  # Debugging error

    return render(request, 'contact.html')


def travel_notice(request):
    if request.method == "POST":
        # Handle Travel By Air form submission
        if "trip-type" in request.POST:  # Check if it's the air travel form
            passenger_names = request.POST.getlist("air_passenger_names")
            trip_type = request.POST.get("trip-type")
            preferred_airline = request.POST.get("preferred_airline")
            preferred_flight_class = request.POST.get("preferred_flight_class")
            ticket_type = request.POST.get("ticket-type")
            flight_type = request.POST.get("flight-type")
            routes = request.POST.get("routes")
            departure_date = request.POST.get("checkin")
            preferred_departure_time = request.POST.get("departure-time")
            arrival_date = request.POST.get("arrival_date")
            preferred_arrival_time = request.POST.get("arrival-time")
            luggage_weight = request.POST.get("luggage_weight")

            # Prepare email content for air travel
            email_subject = f"Official Flight Travel Request - ({departure_date} to {arrival_date})"
            email_body = f"""
            Dear Logistics Department,

            Kindly review the details for a new flight travel request submitted by the employee:

            Passenger Names: {', '.join(passenger_names)}
            Trip Type: {trip_type}
            Preferred Airline: {preferred_airline}
            Preferred Flight Class: {preferred_flight_class}
            Ticket Type: {ticket_type}
            Flight Type: {flight_type}

            Route Details:
            - Routes: {routes}
            - Departure Date: {departure_date}
            - Preferred Departure Time: {preferred_departure_time}

            Return Details:
            - Arrival Date: {arrival_date}
            - Preferred Arrival Time: {preferred_arrival_time}

            Luggage Weight: {luggage_weight}

            Please proceed with the necessary arrangements for the flight. Should you require any additional information, do not hesitate to contact us.

            Best regards,  
            Imperial Crest IT Team
            """


            # Send email for air travel
            send_mail(
                email_subject,
                email_body,
                "settings.DEFAULT_FROM_EMAIL",  # Replace with your email
                ["isaiahdurojaiye9@gmail.com"],  # Replace with the recipient's email
                fail_silently=False,
            )

        # Handle Travel By Road form submission
        elif "vehicle_type" in request.POST:  # Check if it's the car travel form
            vehicle_type = request.POST.get("vehicle_type")
            car_passenger_names = request.POST.getlist("car_passenger_names")  # corrected field name
            journey_type = request.POST.get("journey_type")
            departure_location = request.POST.get("car-departure-location")
            departure_date_car = request.POST.get("departure_date_car")
            preferred_departure_time_car = request.POST.get("car-departure-time")
            destination_location = request.POST.get("car-destination-location")
            return_location = request.POST.get("car-return-location")
            expected_arrival_date = request.POST.get("car-arrival-date")
            expected_arrival_time = request.POST.get("car-arrival-time")
            security_escort = request.POST.get("security-escort")  # corrected field name

            # Prepare email content for car travel
            email_subject_car = "Official Road Travel Request - ({departure_date_car} to {expected_arrival_date})"
            email_body_car = f"""
            Dear Logistics Department,

            Please find below the details for a new road travel request submitted by the employee:

            Passenger Names: {', '.join(car_passenger_names)}
            Vehicle Type Requested: {vehicle_type}
            Journey Type: {journey_type}

            Departure Details:
            - Location: {departure_location}
            - Date: {departure_date_car}
            - Preferred Time: {preferred_departure_time_car}

            Destination: {destination_location}
            Return Location: {return_location}

            **Return Details**:
            - Expected Arrival Date: {expected_arrival_date}
            - Expected Arrival Time: {expected_arrival_time}

            Security Escort Required: {security_escort}

            Please proceed with the necessary arrangements. For further clarification or additional requests, feel free to reach out.

            Best regards,
            Imperial Crest IT Team
            """

            # Send email for car travel
            send_mail(
                email_subject_car,
                email_body_car,
                "settings.DEFAULT_FROM_EMAIL",  # Replace with your email
                ["isaiahdurojaiye9@gmail.com"],  # Replace with the recipient's email
                fail_silently=False,
            )

        return redirect("success")  # Redirect to a success page or similar

    return render(request, "travel.html")

# Requisitions view
def requisitions(request):
    return render(request, "requisitions.html")


def logout_view(request):
    print("logging out")
    logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)


def signup_view(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data["password"])
            user.save()
            messages.success(request, "Account created successfully.")
            return redirect("index")  # Redirect to login page after signup
    else:
        form = SignUpForm()
    return render(request, "signup.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            redirect_url = (
                request.POST.get("next") or request.GET.get("next") or "homepage"
            )
            return redirect(redirect_url)
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "index.html")

def success_view(request):
    return render(request, 'success.html')

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            reset_link = request.build_absolute_uri(f"/reset-password/{uid}/{token}/")
            
            # Render email content
            subject = 'Password Reset Request'
            message = render_to_string('reset_password_email.html', {
                'user': user,
                'reset_link': reset_link
            })
            
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

            messages.success(request, "Password reset instructions have been sent to your email.")
            return redirect('forgot_password')

        except User.DoesNotExist:
            messages.error(request, "No user with this email exists.")
    return render(request, 'forgot_password.html')

def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            if request.method == "POST":
                new_password1 = request.POST.get('new_password1')
                new_password2 = request.POST.get('new_password2')

                if new_password1 == new_password2:
                    user.set_password(new_password1)
                    user.save()

                    messages.success(request, "Password has been successfully reset.")
                    update_session_auth_hash(request, user)  # Keeps the user logged in after password change
                    return redirect('index')
                else:
                    messages.error(request, "Passwords do not match.")
            return render(request, 'reset_password.html')

        else:
            messages.error(request, "The reset link is invalid or has expired.")
            return redirect('forgot_password')

    except (User.DoesNotExist, ValueError):
        messages.error(request, "Invalid user.")
        return redirect('forgot_password')