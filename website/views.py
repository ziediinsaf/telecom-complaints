from flask import Blueprint, render_template, request, flash, jsonify ,redirect, url_for , current_app , session , abort
from flask_login import login_required, current_user
from .models import Note , User , File
from . import db
from werkzeug.utils import redirect
import json
import pandas as pd
import os
from flask import send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash


views = Blueprint('views', __name__)

@views.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response
@views.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
    return response

@views.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@views.route('/', methods=['GET', 'POST'])
def home():
     return render_template('index.html', content="Bienvenue sur la page d'accueil")
       




@views.route('/delete_complaint/<int:note_id>', methods=['DELETE'])
def delete_complaint(note_id):
    try:
        note = Note.query.get_or_404(note_id)
        db.session.delete(note)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Complaint deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500



   



@views.route('/acceuil')
def acceuil():
    return render_template('index.html')


@views.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    if "username" in session:
        if session["account_type"] == "client":
            if request.method == 'POST':
                note_data = request.form.get('note')
                complaint_type = request.form.get('complaintType')
                address = request.form.get('address')
                region = request.form.get('region')
                file = request.files.get('file')

                # Save the file to the server and get the file path
                if file:
                    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
                    file.save(file_path)
                else:
                    file_path = None

                user = User.query.filter_by(id=current_user.id).first()
                new_note = Note(data=note_data, complaint_type=complaint_type, address=address, region=region, technician_id="X", user_id=current_user.id, status="Pending", city=user.city)

                if file_path:
                    new_file = File(filename=file.filename, note=new_note)
                    db.session.add(new_file)

                db.session.add(new_note)
                db.session.commit()
                flash('Complaint added successfully!', 'success')
                return redirect(url_for('views.notes'))

            user_notes = Note.query.filter_by(user_id=current_user.id).all()
            user = User.query.filter_by(id=current_user.id).first()
            return render_template('notes.html', user=current_user, user_notes=user_notes, region=user.region)  # Passer la région ici
        else:
            return redirect("/")
    else:
        return redirect("/")


@views.route('/all_notes', methods=['GET', 'POST'])
def all_notes():
    if "username" in session:
        if session["account_type"] == "admin":
            if request.method == "POST":
                region = request.form.get("region")
                all_users = User.query.with_entities(User.id, User.first_name, User.city, User.phone, User.region).all()
                user_list = [(user.id, user.first_name, user.phone, user.city, user.region) for user in all_users]
                users = pd.DataFrame(user_list, columns=['id', 'first_name', 'phone', 'city', 'region'])
                all_notes = Note.query.filter_by(region=region).all()
                all_tech = User.query.filter_by(account_type="technician").all()
                tech_list = [(tech.id, tech.first_name, tech.region) for tech in all_tech]
                techs = pd.DataFrame(tech_list, columns=['id', 'first_name', 'region'])

            else:
                all_users = User.query.with_entities(User.id, User.first_name, User.city, User.phone, User.region).all()
                user_list = [(user.id, user.first_name, user.phone, user.city, user.region) for user in all_users]
                users = pd.DataFrame(user_list, columns=['id', 'first_name', 'phone', 'city', 'region'])
                all_notes = Note.query.all()
                all_tech = User.query.filter_by(account_type="technician").all()
                tech_list = [(tech.id, tech.first_name, tech.region) for tech in all_tech]
                techs = pd.DataFrame(tech_list, columns=['id', 'first_name', 'region'])

            # Fetch files associated with each note
            note_files_map = {}
            for note in all_notes:
                files = File.query.filter_by(note_id=note.id).all()
                note_files_map[note.id] = files

            return render_template('all_notes.html', all_notes=all_notes, users=users, techs=all_tech, note_files_map=note_files_map)
        else:
            return redirect("/")
    else:
        return redirect("/")             


@views.route('/assign_tech' , methods=['GET', 'POST'])
def assign_tech():
    if "username" in session :
        if session["account_type"]== "admin" :    
            if request.method =="POST":
                tech_id = request.form.get("tech")
                note_id = request.form.get("note_id")
                note = Note.query.filter_by(id=note_id).first()
                note.technician_id = tech_id
                db.session.commit()

               
                return redirect('/all_notes')


 


@views.route('/all_accounts')
def all_accounts():
    if "username" in session:
        if session["account_type"] == "admin":
            # Fetch all technicians from the database
            technicians = User.query.filter_by(account_type='technician').all()
            return render_template('all_accounts.html', technicians=technicians)
        else:
            return redirect("/")
    else:
        return redirect("/")


@views.route('/assigned_notes')
def assigned_notes():
    if "username" in session:
        if session["account_type"] == "technician":
            technician_id = session["user_id"]
            assigned_notes = Note.query.filter_by(technician_id=technician_id).all()
            return render_template('assigned_notes.html', assigned_notes=assigned_notes)
    return redirect("/")

@views.route('/delete_technician/<int:id>', methods=['POST'])
@login_required
def delete_technician(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('Technician has been deleted!', 'success')
    return redirect(url_for('views.all_accounts'))
   

@views.route('/technician_notes')
@login_required
def technician_notes():
    # Récupérer les réclamations (notes) associées au technicien actuellement connecté
    technician_notes = Note.query.filter_by(technician_id=current_user.id).all()
   
    return render_template('technician_notes.html', technician_notes=technician_notes)


@views.route('/update_note/<int:note_id>', methods=['POST'])
def update_note(note_id):
    data = request.json
    address = data.get('address')
    complaint_type = data.get('complaint_type')
    updated_data = data.get('data')

    note = Note.query.get(note_id)  # Récupérer la note par son ID
    if note:
        note.address = address
        note.complaint_type = complaint_type
        note.data = updated_data
        db.session.commit()
        return jsonify({'success': True, 'message': 'Note updated successfully', 'updated_data': updated_data})
    else:
        return jsonify({'success': False, 'message': 'Note not found'}), 404

@views.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
   
    if "username" in session :
         
        if request.method =="POST":      
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            if not check_password_hash(current_user.password, current_password):
                flash('The current password is incorrect.', 'danger')
                return redirect(url_for('views.change_password'))
            if new_password != confirm_password:
                flash('The passwords do not match.', 'danger')
                return redirect(url_for('views.change_password'))
            current_user.password = generate_password_hash(new_password, method='sha256')
            db.session.commit()

            flash('Password updated successfully.', 'success')
            return redirect(url_for('views.change_password'))
        else :
            return render_template("change_password.html", user=current_user)
                 
    else :
        return redirect("/")

@views.route('/update_availability/<int:technician_id>', methods=['POST'])
def update_availability(technician_id):
    if request.method == 'POST':
        new_availability = request.form.get('new_availability')
        technician = User.query.get(technician_id)
        if technician:
            technician.availability = new_availability
            try:
                db.session.commit()
                flash('Availability updated successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating availability: {str(e)}', 'error')
        else:
            flash('Technician not found.', 'error')
    else:
        flash('Invalid request method.', 'error')

    return redirect(url_for('views.technician_notes'))

@views.route('/change_info', methods=['GET', 'POST'])
def change_info():
    if "username" in session:
        username = session['username']
        user = User.query.filter_by(email=username).first()

        if request.method == "POST":
            first_name = request.form.get('first_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            city = request.form.get('city')
            region = request.form.get('region')
            password = request.form.get('password')

            

            if first_name:
                user.first_name = first_name
            if email:
                user.email = email
            if phone:
                user.phone = phone
            if city:
                user.city = city
            if region:
                user.region = region

            db.session.commit()

            # Mettre à jour la session avec les nouvelles informations
            

            flash('Informations updated successfully.', 'success')
            return redirect(url_for('views.change_info'))
        else:
            return render_template("change_info.html", user=current_user)
    else:
        flash('Please login to access this page.', category='danger')
        return redirect("/")


@views.route('/update_info', methods=['POST'])
def update_info():
    data = request.form
    first_name = data.get('first_name')
    email = data.get('email')
    phone = data.get('phone')
    city = data.get('city')
    region = data.get('region')
    password = data.get('password')

    # Vérifiez ici que le mot de passe est correct
    # Utilisation de check_password_hash pour vérifier le mot de passe
    if check_password_hash(current_user.password, password):
        if first_name is not None:
            current_user.first_name = first_name
        if email is not None:
            current_user.email = email
        if phone is not None:
            current_user.phone = phone
        if city is not None:
            current_user.city = city
        if region is not None:
            current_user.region = region
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Informations mises à jour avec succès'})
    else:
        return jsonify({'success': False, 'message': 'Mot de passe incorrect'})



@views.route('/account_admin')
def account_admin():
    if "username" in session:
        if session["account_type"] == "admin":
            # Fetch all admins from the database
            admins = User.query.filter_by(account_type='admin').all()
            return render_template('account_admin.html', admins=admins)
        else:
            return redirect("/")
    else:
        return redirect("/")


@views.route('/delete_admin<int:id>', methods=['POST'])
@login_required
def delete_admin(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('Admin has been deleted!', 'success')
    return redirect(url_for('views.account_admin'))
   


@views.route('/add_comment', methods=['POST'])
@login_required
def add_comment():
    try:
        data = request.json
        note_id = data.get('note_id')
        comment_content = data.get('comment_content')
        retransmit = data.get('retransmit', False)

        # Trouver la note correspondante dans la base de données
        note = Note.query.get(note_id)
        if not note:
            return jsonify({"success": False, "message": "Note not found"}), 404

        # Vérifier si la note a le statut "resolved"
        if note.status.lower() == "resolved":
            return jsonify({"success": False, "message": "Cannot add a comment to a resolved complaint"}), 403

        # Ajouter le commentaire à la base de données
        comment = Comment(content=comment_content, retransmit=retransmit, note_id=note_id)
        db.session.add(comment)
        db.session.commit()

        return jsonify({"success": True, "message": "Comment added successfully"}), 200

    except Exception as e:
        print(e)
        return jsonify({"success": False, "message": "An error occurred while adding the comment"}), 500


@views.route('/complaint_tracking', methods=['GET'])
@login_required
def complaint_tracking():
    if "username" in session and session["account_type"] == "client":
        # Récupérer les réclamations (notes) associées au client actuellement connecté
        user_notes = Note.query.filter_by(user_id=current_user.id).all()
        # Créer un dictionnaire pour mapper les fichiers à chaque note
        note_files_map = {}
        for note in user_notes:
            files = File.query.filter_by(note_id=note.id).all()
            note_files_map[note.id] = files
        return render_template('complaint_tracking.html', user_notes=user_notes, note_files_map=note_files_map)
    else:
        flash('Access denied. Please login as a client to access this page.', 'danger')
        return redirect("/")


@views.route('/mark_not_resolved/<int:complaint_id>', methods=['POST'])
def mark_not_resolved(complaint_id):
    complaint = Note.query.get(complaint_id)
    if complaint:
        if complaint.status == "Resolved":
            complaint.status = "Pending"
            db.session.commit()
            flash('The issue is marked as not resolved.', 'success')
        else:
            flash('The issue is already pending.', 'warning')
    else:
        flash('Complaint not found.', 'error')
    return redirect(url_for('views.complaint_tracking'))



@views.route('/update_status/<int:note_id>', methods=['POST'])
def update_status(note_id):
    if request.method == 'POST':
        new_status = request.form.get('new_status')  
        note = Note.query.get(note_id)
        if note:
            note.status = new_status        
            db.session.commit()
            flash('Note status updated successfully!', category='success')
            return redirect(url_for('views.technician_notes'))
        else:
            flash('Note not found!', category='error')
            return redirect(url_for('views.technician_notes'))
    return redirect(url_for('views.technician_notes'))


@views.route('/send_feedback/<int:note_id>', methods=['POST'])
def send_feedback(note_id):
    try:
        data = request.get_json()
        feedback = data.get('feedback')
        
        # Mettre à jour le champ feedback de la note
        note = Note.query.get_or_404(note_id)
        note.feedback = feedback
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Feedback sent successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500