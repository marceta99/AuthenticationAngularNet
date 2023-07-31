import { Component, NgZone } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-logout',
  templateUrl: './logout.component.html',
  styleUrls: ['./logout.component.css']
})
export class LogoutComponent {

  public colors : any;
  constructor(
     private router : Router,
     private service : AuthService,
     private _ngZone: NgZone) {}

  ngOnInit(){
    this.service.getColors().subscribe({
      next:(colors:any)=>{
        this.colors = colors;
      }
    })
  }
  public logout(){
    this.service.signOutExternal();
    this._ngZone.run(()=>{
      this.router.navigate(['/']).then(()=> window.location.reload());
    });
  }
}
