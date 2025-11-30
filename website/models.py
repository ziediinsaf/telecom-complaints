from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

# Association table for the many-to-many relationship between users and files
note_files_association = db.Table('note_files',
    db.Column('note_id', db.Integer, db.ForeignKey('note.id')),
    db.Column('file_id', db.Integer, db.ForeignKey('file.id'))
)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'))


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(20000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20))
    comment = db.Column(db.String(20000))
    city = db.Column(db.String(20))
    region = db.Column(db.String(100))
    technician_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    technician = db.relationship('User', foreign_keys=[technician_id])
    user = db.relationship('User', foreign_keys=[user_id])
    files = db.relationship('File', backref='note')
    complaint_type = db.Column(db.String(50))
    address = db.Column(db.String(200))
    feedback = db.Column(db.String(20000))  


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    phone = db.Column(db.String(20))
    city = db.Column(db.String(100))
    region = db.Column(db.String(100))
    account_type = db.Column(db.String(20))
    availability = db.Column(db.String(20))
    notes = db.relationship('Note', backref='assigned_technician', foreign_keys="[Note.technician_id]")
    users_notes = db.relationship('Note', backref='user_of_note', foreign_keys="[Note.user_id]")






