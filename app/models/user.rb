class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  has_many :posts

  before_save :set_default_role

  def role?(role_name)
    role == role_name
  end

  private
  def set_default_role
    self.role ||= "user"
  end
end
