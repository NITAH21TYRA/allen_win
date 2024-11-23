from flask import Blueprint, request, jsonify
#from app.models import user
from app.models.user import User
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from app.extensions import bcrypt, db

# Create a Blueprint for user endpoints
#user = Blueprint('user', __name__, url_prefix='/api/v1/user')
user_bp = Blueprint('user', __name__, url_prefix='/api/v1/user')

# Define the registration endpoint


@user_bp.route('/register', methods=['POST'])
def register():
    try:
        # Extract request data
        data = request.json
        name = data.get('name')
        email = data.get('email')
        password_hash = data.get('password')
        role = data.get('role', 'customer')
        phone_number = data.get('phone_number')
        gender = data.get('gender')


            # Validate required fields
        required_fields = ['name', 'email', 'password']
        if not all(data.get(field) for field in required_fields):
            return jsonify({'error': 'All fields are required'}), 400

    # Validate password length
        if len(password) < 6:
            return jsonify({'error': 'Password is too short'}), 400

    # Check if email already exists
        if User.query.filter_by(email=email).first() is not None:
            return jsonify({'error': 'Email already exists'}), 409

    # Hash the password
        hashed_password = bcrypt.generate_password_hash(password_hash).decode('utf-8')

    # Create a new user object
        new_user = User(
        name=name,
        email=email,
        password_hash=hashed_password,  # Store hashed password
        role=role,
        phone_number=phone_number,
        address=address
    )

    # Add new user to the database
        db.session.add(new_user)
        db.session.commit()

    # Response with sanitized user data (without password_hash)
        response_user = {
            
        'id': new_user.id,
        'name': new_user.name,
        'email': new_user.email,
        'phone_number': new_user.phone_number,
        'password_hash': new_user.password_hash,
        'gender': new_user.gender,
        'role': new_user.role,
        'created_at': new_user.created_at,
        'updated_at': new_user.updated_at
    }
        

        return jsonify({
        'message': f'{new_user.name} has been successfully created',
        'user': response_user
    }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



# Define the login endpoint
@user_bp.route('/login', methods=["POST"])
def login():
    try:
        # Extract request data
        data = request.json
        email = data.get("email")
        password_hash = data.get("password")

        # Retrieve user by email
           # Retrieve user by email
        user = User.query.filter_by(email=email).first()

    # Check if user exists and password is correct
        if user and bcrypt.check_password_hash(user.password_hash, password):

        # Create access token
            access_token = create_access_token(identity=user.id)
            return jsonify({'access_token': access_token, 'user_id': user.id}), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500


#Editing a User endpoint
@user_bp.route('/edit/int:user_id', methods=["PUT"]) 
@jwt_required() 
def edit_user(user_id):
    try: 
        current_user_id = get_jwt_identity() 
        loggedInUser = User.query.filter_by(id=current_user_id).first()

    # Get the user to be edited
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        elif loggedInUser.role != 'admin' and user.id != current_user_id:
            return jsonify({'error': 'You are not authorized to update user details'}), 403

    # Get request data
        data = request.get_json()
    
    # Update user fields if provided in request
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        user.address = data.get('gender', user.gender)
        user.password_hash = data.get('password_hash',user.password_hash)
        user.phone_number = data.get('phone_number', user.phone_number)
        user.role = data.get('role', user.role)
    
    # Update password if provided
        if 'password' in data:
            password = data['password']
        if len(password) < 6:
            return jsonify({'error': 'Password must have at least 6 characters'}), 400
        user.password = generate_password_hash(password)
    
    # Commit changes to the database
        db.session.commit()

        return jsonify({
        'message': user.name + "'s details have been successfully updated",
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone_number': user.phone_number,
            'password_hash': user.password_hash,
            'role': user.role,
            'updated_at': user.updated_at,
        }
    }), 200

    except Exception as e:
        db.session.rollback()
    return jsonify({'error': str(e)}), 500

# Define the delete user endpoint
@user_bp.route('/delete/int:user_id', methods=["DELETE"]) 
@jwt_required() 
def delete_user(user_id): 
    try:
        current_user_id = get_jwt_identity()
        loggedInUser = User.query.filter_by(id=current_user).first()

    #Get current user by id
        user = User.query.filter_by(id=id).first()

        if not user:
            return jsonify({'error': 'Unauthorized access'}), HTTP_404_NOT_FOUND
        elif loggedInUser.role!='admin':
            return jsonify({'error': 'You are not authorised to delete this user details'})
        else:
            name = request.get_json().get('name',user.name)
            email = request.get_json().get('email',user.email)
            address = request.get_json().get('gender',user.gender)
            phone_number = request.get_json().get('phone_number',user.phone_number)
            role  = request.get_json().get('role',user.role)  

       
   
    
    # Retrieve user by ID
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

    # Delete user from database
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'User deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

#Get all users
# @user.route('/users', methods=['GET']) 
# def get_all_users(): 
#     try: # Retrieve all users from the database 
#         users = User.query.all()
@user_bp.route('/users', methods=["GET"])
@jwt_required()
def get_current_user():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=current_user_id).first()

        if user:
            # Serialize user data (exclude sensitive fields like password_hash)
            serialized_user = {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'phone_number': user.phone_number,
                'gender': user.gender,
                'role': user.role,
                'created_at': user.created_at,
                'updated_at': user.updated_at
            }
            return jsonify({'user': serialized_user}), 200
        else:
            return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


